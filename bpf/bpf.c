/*
 * Copyright (c) 2021 Alibaba Group Holding Limited
 * Express UDP is licensed under Mulan PSL v2.
 * You can use this software according to the terms and conditions of the Mulan PSL v2.
 * You may obtain a copy of Mulan PSL v2 at:
 *          http://license.coscl.org.cn/MulanPSL2
 * THIS SOFTWARE IS PROVIDED ON AN "AS IS" BASIS, WITHOUT WARRANTIES OF ANY KIND,
 * EITHER EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO NON-INFRINGEMENT,
 * MERCHANTABILITY OR FIT FOR A PARTICULAR PURPOSE.
 * See the Mulan PSL v2 for more details.
 *
 */

#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <malloc.h>
#include <stdbool.h>

#include "bpf.h"

#include "log.h"

#define pr_err(b,   fmt, ...) logerr(b->log,   fmt, ##__VA_ARGS__)
#define pr_warn(b,  fmt, ...) logwrn(b->log,   fmt, ##__VA_ARGS__)
#define pr_debug(b, fmt, ...) logdebug(b->log, fmt, ##__VA_ARGS__)

struct map{
	int fd;
	int offset;
	struct bpf_map_def def;
};

static int bpf_prog_load(enum bpf_prog_type type,
              	  const struct bpf_insn *insns, int insn_cnt,
              	  const char *license, char *log, int log_size)
{
        union bpf_attr attr = {
                .prog_type = type,
                .insns     = ptr_to_u64(insns),
                .insn_cnt  = insn_cnt,
                .license   = ptr_to_u64(license),
                .log_buf   = ptr_to_u64(log),
                .log_size  = log_size,
                .log_level = 1,
        };

        return sys_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int bpf_create_map_xattr(struct bpf_map_def *m)
{
	union bpf_attr attr;
	int ret;

	memset(&attr, '\0', sizeof(attr));

	strncpy(attr.map_name, m->name, sizeof(attr.map_name) - 1);

	attr.map_type     = m->type;
	attr.key_size     = m->key_size;
	attr.value_size   = m->value_size;
	attr.max_entries  = m->max_entries;
	attr.map_flags    = m->map_flags;
	attr.inner_map_fd = m->inner_map_fd;

	ret =  sys_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));

	if (m->type == BPF_MAP_TYPE_ARRAY_OF_MAPS ||
	    m->type == BPF_MAP_TYPE_HASH_OF_MAPS)
		close(m->inner_map_fd);

	return ret;
}

static int bpf_close_all_map(struct bpf *b)
{
	struct map *m;
	int i;

	for (i = 0; i < b->maps_n; ++i) {
		m = b->maps + i;
		if (m->fd > -1)
			close(m->fd);
	}
	return 0;
}

static int bpf_map_init(struct bpf *b, struct map *m)
{
	struct bpf_map_def *def;
	int fd;

	def = &m->def;

	if (b->map_filter) {
		if (b->map_filter(def, b->map_filter_data)) {
			pr_warn(b, "bpf map filter fail. %s.\n",
				m->def.name);
			return -1;
		}
	}

	fd = bpf_create_map_xattr(def);

	pr_debug(b, "create map %s %d\n", m->def.name, fd);

	if (fd < 0) {
		pr_warn(b, "bpf map create fail. %s. strerr: %s\n",
			m->def.name, strerror(errno));
		return -1;
	}

	m->fd = fd;
	return 0;
}

static int bpf_insn_set_map_fd(struct bpf *b, GElf_Sym *sym, struct bpf_insn *insn)
{
	struct map *m;
	int i;

	for (i = 0; i < b->maps_n; ++i) {

		m = b->maps + i;

		if (m->offset != sym->st_value)
			continue;

		if (m->fd == -1) {
			if (bpf_map_init(b, m))
				return -1;
		}

		insn[0].src_reg = BPF_PSEUDO_MAP_FD;
		insn[0].imm = m->fd;

		return 0;
	}

	return -1;
}

static int bpf_elf_do_rel(struct bpf *b, int insn_idx, const char *name,
			  GElf_Sym *sym, GElf_Rel *rel)
{
	struct bpf_insn *insn;
	__u32 shdr_idx = sym->st_shndx;

	insn = ((struct bpf_insn *)b->ins.p) + insn_idx;

	if (shdr_idx == b->maps_idx)
		return bpf_insn_set_map_fd(b, sym, insn);

	/* sub-program call relocation */
	if (insn->code == (BPF_JMP | BPF_CALL)) {
		pr_err(b, "not support sub-program relocation\n");
		return -1;
	}

	if (insn->code != (BPF_LD | BPF_IMM | BPF_DW)) {
		pr_warn(b, "invalid relo for insns[%d].code 0x%x\n",
			insn_idx, insn->code);
		return -1;
	}


	if (!shdr_idx || shdr_idx >= SHN_LORESERVE) {
		pr_warn(b, "invalid relo for \'%s\' in special section 0x%x; forgot to initialize global var?..\n",
			name, shdr_idx);
		return -1;
	}

	pr_err(b, "not support relocation %s, idx: %d\n", name, insn_idx);

	return -1;
}

static int bpf_elf_maps_rel(struct bpf *b)
{
	int i;
	char *name;
	Elf_Scn *scn;
	GElf_Shdr sh, *shdr;
	Elf_Data *data;

	scn = b->rel_scn;

	if (!scn)
		return 0;

	if (gelf_getshdr(scn, &sh) != &sh) {
		return -1;
	}

	name = elf_strptr(b->elf, b->ehdr.e_shstrndx, sh.sh_name);
	if (!name) {
		return -1;
	}

	data = elf_getdata(scn, 0);
	if (!data) {
		return -1;
	}

	shdr = &sh;

	Elf_Data *symbols = b->symbols;
	int err, nrels;

	nrels = shdr->sh_size / shdr->sh_entsize;

	for (i = 0; i < nrels; i++) {
		const char *name;
		__u32 insn_idx;
		GElf_Sym sym;
		GElf_Rel rel;

		if (!gelf_getrel(data, i, &rel)) {
			return -1;
		}
		if (!gelf_getsym(symbols, GELF_R_SYM(rel.r_info), &sym)) {
			return -1;
		}
		if (rel.r_offset % sizeof(struct bpf_insn))
			return -1;

		insn_idx = rel.r_offset / sizeof(struct bpf_insn);
		name = elf_strptr(b->elf, b->ehdr.e_shstrndx, sym.st_name) ? : "<?>";

		err = bpf_elf_do_rel(b, insn_idx, name, &sym, &rel);
		if (err)
			return err;
	}

	return 0;
}

static int bpf_elf_collect_maps(struct bpf *b)
{
	Elf_Data *symbols = b->symbols;
	int i, map_def_sz = 0, nr_maps = 0, nr_syms;
	Elf_Data *data = NULL;
	Elf_Scn *scn;

	if (b->maps_idx < 0)
		return 0;

	if (!symbols)
		return -EINVAL;

	scn = elf_getscn(b->elf, b->maps_idx);
	if (scn)
		data = elf_getdata(scn, NULL);

	if (!scn || !data) {
		pr_warn(b, "failed to get Elf_Data from map section %d\n",
			b->maps_idx);
		return -EINVAL;
	}

	/*
	 * Count number of maps. Each map has a name.
	 * Array of maps is not supported: only the first element is
	 * considered.
	 *
	 * TODO: Detect array of map and report error.
	 */
	nr_syms = symbols->d_size / sizeof(GElf_Sym);
	for (i = 0; i < nr_syms; i++) {
		GElf_Sym sym;

		if (!gelf_getsym(symbols, i, &sym))
			continue;

		if (sym.st_shndx != b->maps_idx)
			continue;

		nr_maps++;
	}


	if (!data->d_size || nr_maps == 0 || (data->d_size % nr_maps) != 0) {
		pr_warn(b, "unable to determine map definition size section, %d maps in %zd bytes\n",
			nr_maps, data->d_size);
		return -EINVAL;
	}

	map_def_sz = data->d_size / nr_maps;

	b->maps_n = 0;
	b->maps = malloc(sizeof(*b->maps) * nr_maps);

	/* Fill obj->maps using data in "maps" section.  */
	for (i = 0; i < nr_syms; i++) {
		GElf_Sym sym;
		char *map_name;
		struct bpf_map_def *def;

		struct map *map;

		if (!gelf_getsym(symbols, i, &sym))
			continue;
		if (sym.st_shndx != b->maps_idx)
			continue;

		map = b->maps + b->maps_n;

		map_name = elf_strptr(b->elf, b->strtabidx, sym.st_name);
		if (!map_name) {
			pr_warn(b, "failed to get map #%d name sym string for obj\n",
				i);
			return -1;
		}

		if (sym.st_value + map_def_sz > data->d_size) {
			pr_warn(b, "corrupted maps section last map \"%s\" too small\n",
				map_name);
			return -EINVAL;
		}

		map->offset = sym.st_value;
		map->fd = -1;


		def = (struct bpf_map_def *)(data->d_buf + sym.st_value);
		def->name = map_name;

		/*
		 * If the definition of the map in the object file fits in
		 * bpf_map_def, copy it.  Any extra fields in our version
		 * of bpf_map_def will default to zero as a result of the
		 * calloc above.
		 */
		if (map_def_sz <= sizeof(struct bpf_map_def)) {
			memcpy(&map->def, def, map_def_sz);
		} else {
			/*
			 * Here the map structure being read is bigger than what
			 * we expect, truncate if the excess bits are all zero.
			 * If they are not zero, reject this map as
			 * incompatible.
			 */
			char *c;

			for (c = ((char *)def) + sizeof(struct bpf_map_def);
			     c < ((char *)def) + map_def_sz; c++) {
				if (*c != 0) {
					pr_warn(b, "maps section: \"%s\" has unrecognized, non-zero options\n",
						map_name);
					return -EINVAL;
				}
			}
			memcpy(&map->def, def, sizeof(struct bpf_map_def));
		}
		++b->maps_n;

		pr_debug(b, "map %d is \"%s\"  type: %d key size: %d value size: %d num: %d\n",
			 i, map->def.name,
			 map->def.type,
			 map->def.key_size,
			 map->def.value_size,
			 map->def.max_entries);
	}
	return 0;
}

static Elf_Scn *bpf_elf_find_rel_sec(Elf *elf, int idx)
{
	Elf_Scn *scn = NULL;

	GElf_Shdr sh;

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		if (gelf_getshdr(scn, &sh) != &sh) {
			return NULL;
		}

		if (sh.sh_type != SHT_REL)
			continue;

		if (sh.sh_info != idx)
			continue;

		return scn;
	}

	return NULL;
}

static int bpf_elf_collect_scn(struct bpf *b)
{
	Elf *elf = b->elf;
	GElf_Ehdr *ep = &b->ehdr;

	Elf_Scn *scn = NULL;
	int idx = 0;

	b->maps_idx = -1;


	/* Elf is corrupted/truncated, avoid calling elf_strptr. */
	if (!elf_rawdata(elf_getscn(elf, ep->e_shstrndx), NULL)) {
		pr_warn(b, "failed to get e_shstrndx from elf\n");
		return -1;
	}

	while ((scn = elf_nextscn(elf, scn)) != NULL) {
		char *name;
		GElf_Shdr sh;
		Elf_Data *data;

		idx++;
		if (gelf_getshdr(scn, &sh) != &sh) {
			pr_warn(b, "failed to get section(%d) header from bpf elf\n",
				idx);
			return -1;
		}

		name = elf_strptr(elf, ep->e_shstrndx, sh.sh_name);
		if (!name) {
			pr_warn(b, "failed to get section(%d) name from bpf elf\n",
				idx);
			return -1;
		}

		data = elf_getdata(scn, 0);
		if (!data) {
			pr_warn(b, "failed to get section(%d) data from %s\n",
				idx, name);
			return -1;
		}

		/* ................... */

		if (strcmp(name, b->target_proc) == 0) {
			b->ins.p = data->d_buf;
			b->ins.size = data->d_size;
			b->rel_scn = bpf_elf_find_rel_sec(elf, idx);
			continue;
		}

		if (strcmp(name, "license") == 0) {
			b->license.p    = data->d_buf;
			b->license.size = data->d_size;

		} else if (strcmp(name, "version") == 0) {
			b->version.p    = data->d_buf;
			b->version.size = data->d_size;

		} else if (strcmp(name, "maps") == 0) {
			b->maps_idx = idx;

		} else if (sh.sh_type == SHT_SYMTAB) {
			b->symbols = data;
			b->symbols_shndx = idx;
			b->strtabidx = sh.sh_link;

		} else if (sh.sh_type == SHT_PROGBITS && data->d_size > 0) {
		} else if (sh.sh_type == SHT_REL) {
		} else {
		}
	}

	return 0;
}


static int _bpf_load(struct bpf *b, char *e, int size)
{
	Elf *elf;
	int ret;
	char log[1024 * 500];

	elf = elf_memory(e, size);
	if (!elf)
		return -1;

	b->elf = elf;

	if (!gelf_getehdr(elf, &b->ehdr)) {
		ret = -1;
		pr_warn(b, "failed to get EHDR from bpf elf\n");
		goto err;
	}

	ret = bpf_elf_collect_scn(b);
	if (ret)
		goto err;


	ret = bpf_elf_collect_maps(b);
	if (ret)
		goto err;

	ret = bpf_elf_maps_rel(b);
	if (ret) {
		bpf_close_all_map(b);
		pr_warn(b, "bpf maps rel fail\n");
		goto err;
	}

	ret = bpf_prog_load(b->type,
			    (const struct bpf_insn *)b->ins.p,
			    b->ins.size/sizeof(struct bpf_insn),
			    b->license.p,
			    log,
			    sizeof(log));
	if (ret < 0) {
		printf("==== bpf load log ====\n%s\n", log);
		printf("bpf load err: %s\n", strerror(errno));
	}

	b->prog_fd = ret;

err:
	elf_end(elf);
	return ret;
}

void bpf_close(struct bpf *b)
{
	bpf_close_all_map(b);

	if (b->prog_fd > -1)
		close(b->prog_fd);

	if (b->maps)
		free(b->maps);
}

int bpf_load(struct bpf *b, char *proc,
	     enum bpf_prog_type type, char *elf, int size)
{
	int ret;

	b->prog_fd = -1;
	b->target_proc = proc;
	b->type = type;

	ret = _bpf_load(b, elf, size);

	return ret;
}

int bpf_map_get(struct bpf *b, const char *name)
{
	int i;
	for (i = 0; i < b->maps_n; ++i) {
		if (0 == strcmp(name, b->maps[i].def.name))
			return b->maps[i].fd;
	}

	return -1;
}

int bpf_map_get_idx(struct bpf *b, unsigned int i, int *fd)
{
	if (i >= b->maps_n)
		return -1;

	*fd = b->maps[i].fd;

	return 0;
}


