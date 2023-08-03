
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>

#include "route6.h"

int main(int argc, char *argv[])
{
	struct route_rule6 *rt6;
	struct route6 *r6;
	struct in6_addr a6;
	struct log log = {};
	char buf[100];
	int ret;

	log.level = LOG_LEVEL_INFO;

	if (argc == 3) {
		if (strcmp("debug", argv[2]) == 0)
			log.level = LOG_LEVEL_DEBUG;
	}

	r6 = route6_init(&log);

	if (argc == 1)
		goto end;

	ret = inet_pton(AF_INET6, argv[1], &a6);

	rt6 = route6_lookup(r6, &a6);

	printf("\n");

	printf("target: %s\n", argv[1]);
	printf("ret:    %d\n", ret);

	printf("ifid:   %d\n", rt6->ifid);
	printf("index:  %d\n", rt6->index);

	printf("dstlen: %d\n", rt6->dst_len);

	inet_ntop(AF_INET6, &rt6->dst, buf, sizeof(buf));
	printf("dst:    %s\n", buf);

	inet_ntop(AF_INET6, &rt6->next_hop, buf, sizeof(buf));
	printf("via:    %s\n", buf);

	inet_ntop(AF_INET6, &rt6->pref_src, buf, sizeof(buf));
	printf("src:    %s\n", buf);

end:
	route6_free(r6);

	return 0;
}
