#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <libnet.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/netfilter.h>		/* for NF_ACCEPT */
#include <errno.h>
#include <string>
#include <string.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

char *blockedHost;
bool isBlocked;

void usage(void)
{
	printf("Wrong usage!\n");
	printf("syntax: ./netfilter-test <host>\n");
	printf("sample: ./netfilter-test test.gilgil.net\n");

	return;
}

void dump(unsigned char* buf, int size) {
	unsigned char http[2048];
	struct libnet_tcp_hdr *tcph;
	struct libnet_ipv4_hdr *ipv4 = (libnet_ipv4_hdr *)buf;
	int iplen = ipv4->ip_hl * 4;;
	isBlocked = false;

	if (ipv4->ip_p == 6) {
		tcph = (libnet_tcp_hdr *)(buf + iplen);
		if (ntohs(tcph->th_dport) == 80 || ntohs(tcph->th_sport) == 80) {
			int tcplen = tcph->th_off * 4;
			memcpy(http, buf + tcplen + iplen, size - iplen - tcplen);
			http[size - iplen - tcplen] = '\0';
			unsigned char *hostp = (unsigned char *)strstr((const char *)http, "Host:");
			if (hostp) {
				char *check = (char *)malloc(strlen(blockedHost) + 10);
				strncpy(check, (char *)(hostp + 6), strlen(blockedHost));
				if (!strcmp(check, blockedHost)) {
					printf("\n\n*** You cannot access <%s> ***\n\n", blockedHost);
					isBlocked = true;
				}
			}
		}
	}
}


/* returns packet id */
static u_int32_t print_pkt(struct nfq_data *tb)
{
	int id = 0;
	struct nfqnl_msg_packet_hdr *ph;
	struct nfqnl_msg_packet_hw *hwph;
	u_int32_t mark, ifi;
	int ret;
	unsigned char *data;

	ph = nfq_get_msg_packet_hdr(tb);
	if (ph) {
		id = ntohl(ph->packet_id);
		printf("hw_protocol=0x%04x hook=%u id=%u ",
			ntohs(ph->hw_protocol), ph->hook, id);
	}

	hwph = nfq_get_packet_hw(tb);
	if (hwph) {
		int i, hlen = ntohs(hwph->hw_addrlen);

		printf("hw_src_addr=");
		for (i = 0; i < hlen - 1; i++)
			printf("%02x:", hwph->hw_addr[i]);
		printf("%02x ", hwph->hw_addr[hlen - 1]);
	}

	mark = nfq_get_nfmark(tb);
	if (mark)
		printf("mark=%u ", mark);

	ifi = nfq_get_indev(tb);
	if (ifi)
		printf("indev=%u ", ifi);

	ifi = nfq_get_outdev(tb);
	if (ifi)
		printf("outdev=%u ", ifi);
	ifi = nfq_get_physindev(tb);
	if (ifi)
		printf("physindev=%u ", ifi);

	ifi = nfq_get_physoutdev(tb);
	if (ifi)
		printf("physoutdev=%u ", ifi);

	ret = nfq_get_payload(tb, &data);
	if (ret >= 0)
	{
		dump(data, ret);
		printf("payload_len=%d ", ret);
	}

	fputc('\n', stdout);

	return id;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
	struct nfq_data *nfa, void *data)
{
	u_int32_t id = print_pkt(nfa);
	printf("entering callback\n");
	if (isBlocked) return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
	return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}

int main(int argc, char **argv)
{
	struct nfq_handle *h;
	struct nfq_q_handle *qh;
	struct nfnl_handle *nh;
	int fd;
	int rv;
	char buf[4096] __attribute__((aligned));

	if (argc != 2) usage();
	blockedHost = argv[1];

	printf("opening library handle\n");
	h = nfq_open();
	if (!h) {
		fprintf(stderr, "error during nfq_open()\n");
		exit(1);
	}

	printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
	if (nfq_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_unbind_pf()\n");
		exit(1);
	}

	printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
	if (nfq_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nfq_bind_pf()\n");
		exit(1);
	}

	printf("binding this socket to queue '0'\n");
	qh = nfq_create_queue(h, 0, &cb, NULL);
	if (!qh) {
		fprintf(stderr, "error during nfq_create_queue()\n");
		exit(1);
	}

	printf("setting copy_packet mode\n");
	if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet_copy mode\n");
		exit(1);
	}

	fd = nfq_fd(h);

	for (;;) {
		if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
			printf("pkt received\n");
			nfq_handle_packet(h, buf, rv);
			continue;
		}
		/* if your application is too slow to digest the packets that
		* are sent from kernel-space, the socket buffer that we use
		* to enqueue packets may fill up returning ENOBUFS. Depending
		* on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
		* the doxygen documentation of this library on how to improve
		* this situation.
		*/
		if (rv < 0 && errno == ENOBUFS) {
			printf("losing packets!\n");
			continue;
		}
		perror("recv failed");
		break;
	}

	printf("unbinding from queue 0\n");
	nfq_destroy_queue(qh);

#ifdef INSANE
	/* normally, applications SHOULD NOT issue this command, since
	* it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nfq_unbind_pf(h, AF_INET);
#endif

	printf("closing library handle\n");
	nfq_close(h);

	exit(0);
}