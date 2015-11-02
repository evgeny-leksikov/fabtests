/*
 * Copyright (c) 2013-2015 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under the BSD license
 * below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AWV
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <assert.h>

#include <rdma/fabric.h>
#include <rdma/fi_endpoint.h>
#include <rdma/fi_rma.h>
#include <rdma/fi_cm.h>
#include <rdma/fi_errno.h>
#include <shared.h>


struct fi_rma_iov local, remote;

struct fi_context fi_ctx_write;
struct fi_context fi_ctx_read;

enum ft_rma_msg_type
{
    FT_RMA_READV,
    FT_RMA_WRITEV,
    FT_RMA_READMSG,
    FT_RMA_WRITEMSG,
};

static enum ft_rma_msg_type op_type = FT_RMA_WRITEV;

#ifndef min
#  define min(a, b) ((a) < (b) ? (a) : (b))
#endif

#ifndef max
#  define max(a, b) ((a) > (b) ? (a) : (b))
#endif

#define IOV_LIMIT min(1024, fi->tx_attr->rma_iov_limit)

/*static char * welcome_text = "Hello from Client!";*/

static void* vbuf = 0;
static struct fid_mr* vmr = 0;

static int exchange_keys(struct fi_rma_iov *local_iov, struct fi_rma_iov *peer_iov)
{
	struct fi_rma_iov *rma_iov;
	int ret;

	if (opts.dst_addr) {
		rma_iov = tx_buf + ft_tx_prefix_size();
		rma_iov->addr = fi->domain_attr->mr_mode == FI_MR_SCALABLE ?
				0 : local_iov->addr;
		rma_iov->key = local_iov->key;
        rma_iov->len = local_iov->len;
		ret = ft_tx(sizeof *rma_iov);
		if (ret)
			return ret;

		ret = ft_get_rx_comp(rx_seq);
		if (ret)
			return ret;

		rma_iov = rx_buf + ft_rx_prefix_size();
		*peer_iov = *rma_iov;
		ret = ft_post_rx(rx_size);
	} else {
		ret = ft_get_rx_comp(rx_seq);
		if (ret)
			return ret;

		rma_iov = rx_buf + ft_rx_prefix_size();
		*peer_iov = *rma_iov;
		ret = ft_post_rx(rx_size);
		if (ret)
			return ret;

		rma_iov = tx_buf + ft_tx_prefix_size();
		rma_iov->addr = fi->domain_attr->mr_mode == FI_MR_SCALABLE ?
				0 : local_iov->addr;
		rma_iov->key = local_iov->key;
        rma_iov->len = local_iov->len;
		ret = ft_tx(sizeof *rma_iov);
	}

	return ret;
}

static int alloc_ep_res(struct fi_info *fi)
{
	int ret;

    int iov_limit = IOV_LIMIT;

    int minlen = (1 + iov_limit) * iov_limit * sizeof(int);

    if(opts.transfer_size < minlen)
        opts.transfer_size = minlen;

	ret = ft_alloc_active_res(fi);
	if (ret)
		return ret;

    vbuf = malloc(opts.transfer_size);

    memset(vbuf, 0, opts.transfer_size);

	ret = fi_mr_reg(domain, vbuf, opts.transfer_size,
			FI_REMOTE_READ | FI_REMOTE_WRITE, 0, FT_MR_KEY, 0, &vmr, NULL);

	if (ret) {
		FT_PRINTERR("fi_mr_reg", ret);
		return ret;
	}

    return 0;
}

static int init_fabric(void)
{
	char *node, *service;
	uint64_t flags = 0;
	int ret;

	ret = ft_read_addr_opts(&node, &service, hints, &flags, &opts);
	if (ret)
		return ret;

	ret = fi_getinfo(FT_FIVERSION, node, service, flags, hints, &fi);
	if (ret) {
		FT_PRINTERR("fi_getinfo", ret);
		return ret;
	}

	ret = ft_open_fabric_res();
	if (ret)
		return ret;

	ret = alloc_ep_res(fi);
	if (ret)
		return ret;

	ret = ft_init_ep();
	if (ret)
		return ret;

	return 0;
}

static int run_test(void)
{
	int ret = 0;
    int i;
    int j;

	ret = init_fabric();
	if (ret)
		return ret;

	ret = ft_init_av();
	if (ret)
		return ret;

    struct fi_rma_iov local = {.addr = (uint64_t)vbuf, .len = opts.transfer_size, .key = fi_mr_key(vmr)};
    struct fi_rma_iov remote = {0};
    exchange_keys(&local, &remote);
    /*printf("(%d) local: %p:%ld:%d\n", getpid(), vbuf, local.key, (int)local.len);*/
    /*printf("(%d) remote: %p:%ld:%d\n", getpid(), (void*)remote.addr, remote.key, (int)remote.len);*/

    /*ft_sync();*/

	if(opts.dst_addr)
    {  /* client */
        if(op_type == FT_RMA_WRITEV)
        {
            fprintf(stdout, "RMA write to server\n");

            int iov_limit = IOV_LIMIT;
            struct iovec iov[iov_limit];
            int* b = (int*)vbuf;

            for(i = 1; i <= iov_limit; i++)
            {
                iov[i - 1].iov_base = b;
                iov[i - 1].iov_len = i * sizeof(*b);
                for(j = 0; j < i; j++)
                {
                    assert((void*)(b + 1) < (void*)(vbuf + opts.transfer_size));
                    *b = j + 1;
                    b++;
                }
                b += i;
            }

            ret = fi_writev(ep, iov, 0, iov_limit,
                    remote_fi_addr, remote.addr, remote.key, &fi_ctx_write);
            if (ret)
                return ret;

            ret = ft_get_tx_comp(++tx_seq);
            if (ret)
                return ret;
        }
        else if(op_type == FT_RMA_WRITEMSG)
        {
            fprintf(stdout, "RMA write msg to server\n");

            int iov_limit = IOV_LIMIT;
            struct iovec iov[iov_limit];
            struct fi_rma_iov rma_iov[iov_limit];
            void* desc[iov_limit];
            struct fi_msg_rma msg = {
                .msg_iov = iov, .desc = desc, .iov_count = iov_limit, .addr = remote_fi_addr,
                .rma_iov = rma_iov, .rma_iov_count = iov_limit, .context = &fi_ctx_write, .data = 0};


            int* b = (int*)vbuf;
            int* d = (int*)remote.addr;

            memset(desc, 0, sizeof(desc));

            for(i = 1; i <= iov_limit; i++)
            {
                iov[i - 1].iov_base = b;
                iov[i - 1].iov_len = i * sizeof(*b);
                for(j = 0; j < i; j++)
                {
                    assert((void*)(b + 1) < (void*)(vbuf + opts.transfer_size));
                    *b = j + 1;
                    b++;
                }
                b += i;

                rma_iov[i - 1].addr = (uint64_t)d;
                rma_iov[i - 1].len = i * sizeof(*d);
                rma_iov[i - 1].key = remote.key;
                d += i + 1;
            }

            ret = fi_writemsg(ep, &msg, 0);
            if (ret)
                return ret;

            ret = ft_get_tx_comp(++tx_seq);
            if (ret)
                return ret;
        }
        else if(op_type == FT_RMA_READV)
        {
            memset(vbuf, 0, opts.transfer_size);
            fprintf(stdout, "RMA read from client\n");

            int iov_limit = IOV_LIMIT;
            struct iovec iov[iov_limit];
            int* b = (int*)vbuf;

            for(i = 1; i <= iov_limit; i++)
            {
                iov[i - 1].iov_base = b;
                iov[i - 1].iov_len = i * sizeof(*b);
                b += i * 2;
            }

            ft_sync();
            ret = fi_readv(ep, iov, 0, iov_limit,
                    remote_fi_addr, remote.addr, remote.key, &fi_ctx_read);

            if (ret)
                return ret;

            ret = ft_get_tx_comp(++tx_seq);

            if (ret)
                return ret;

            b = (int*)vbuf;
            for(i = 1; i <= iov_limit; i++)
            {
                for(j = 0; j < i; j++)
                {
                    assert((void*)(b + 1) < (void*)(vbuf + opts.transfer_size));
                    if(*b != j + 1)
                    {
                        printf("incorrect data at offset: (%d:%d): %d, expected: %d\n", i, j, *b, j + 1);
                        return EXIT_FAILURE;
                    }
                    b++;
                }
                b += i;
            }

            ft_sync();
        }
        else if(op_type == FT_RMA_READMSG)
        {
            memset(vbuf, 0, opts.transfer_size);
            fprintf(stdout, "RMA read from client\n");

            int iov_limit = IOV_LIMIT;
            struct iovec iov[iov_limit];
            struct fi_rma_iov rma_iov[iov_limit];
            void* desc[iov_limit];
            struct fi_msg_rma msg = {
                .msg_iov = iov, .desc = desc, .iov_count = iov_limit, .addr = remote_fi_addr,
                .rma_iov = rma_iov, .rma_iov_count = iov_limit, .context = &fi_ctx_write, .data = 0};


            int* b = (int*)vbuf;
            int* d = (int*)remote.addr;

            for(i = 1; i <= iov_limit; i++)
            {
                iov[i - 1].iov_base = b;
                iov[i - 1].iov_len = i * sizeof(*b);
                b += i * 2;

                rma_iov[i - 1].addr = (uint64_t)d;
                rma_iov[i - 1].len = i * sizeof(*d);
                rma_iov[i - 1].key = remote.key;
                d += i + 1;
            }

            ft_sync();
            ret = fi_readmsg(ep, &msg, 0);

            if (ret)
                return ret;

            ret = ft_get_tx_comp(++tx_seq);

            if (ret)
                return ret;

            b = (int*)vbuf;
            for(i = 1; i <= iov_limit; i++)
            {
                for(j = 0; j < i; j++)
                {
                    assert((void*)(b + 1) < (void*)(vbuf + opts.transfer_size));
                    if(*b != j + 1)
                    {
                        printf("incorrect data at offset: (%d:%d): %d, expected: %d\n", i, j, *b, j + 1);
                        return EXIT_FAILURE;
                    }
                    b++;
                }
                b += i;
            }

            ft_sync();
        }
		fprintf(stdout, "Received a completion event for RMA write\n");
	}
    else
    { /* server */
        if(op_type == FT_RMA_WRITEV)
        {
            ret = ft_get_rx_comp(rx_seq);
            if (ret)
                return ret;

            fprintf(stdout, "Received data from Client\n");

            int iov_limit = IOV_LIMIT;
            int* b = (int*)vbuf;
            for(i = 1; i <= iov_limit; i++)
            {
                for(j = 0; j < i; j++)
                {
                    assert((void*)(b + 1) < (void*)(vbuf + opts.transfer_size));
                    if(*b != j + 1)
                    {
                        printf("incorrect data at offset: (%d:%d): %d, expected: %d\n", i, j, *b, j + 1);
                        return EXIT_FAILURE;
                    }
                    b++;
                }
            }
        }
        else if(op_type == FT_RMA_WRITEMSG)
        {
            ret = ft_get_rx_comp(rx_seq);
            if (ret)
                return ret;

            fprintf(stdout, "Received msg from Client\n");

            int iov_limit = IOV_LIMIT;
            int* b = (int*)vbuf;
            for(i = 1; i <= iov_limit; i++)
            {
                for(j = 0; j < i; j++)
                {
                    assert((void*)(b + 1) < (void*)(vbuf + opts.transfer_size));
                    if(*b != j + 1)
                    {
                        printf("incorrect data at offset: (%d:%d): %d, expected: %d\n", i, j, *b, j + 1);
                        return EXIT_FAILURE;
                    }
                    b++;
                }
                b++;
            }
        }
        else if(op_type == FT_RMA_READV)
        {
            /* prepare read buffer */
            int i;
            int j;
            int iov_limit = IOV_LIMIT;

            int* b = (int*)vbuf;
            for(i = 1; i <= iov_limit; i++)
            {
                for(j = 0; j < i; j++)
                {
                    assert((void*)(b + 1) < (void*)(vbuf + opts.transfer_size));
                    *b = j + 1;
                    b++;
                }
            }
            ft_sync();
            ft_sync();
        }
        else if(op_type == FT_RMA_READMSG)
        {
            /* prepare read buffer */
            int i;
            int j;
            int iov_limit = IOV_LIMIT;

            int* b = (int*)vbuf;
            for(i = 1; i <= iov_limit; i++)
            {
                for(j = 0; j < i; j++)
                {
                    assert((void*)(b + 1) < (void*)(vbuf + opts.transfer_size));
                    *b = j + 1;
                    b++;
                }
                b++;
            }
            ft_sync();
            ft_sync();
        }

	}

	/* TODO: need support for finalize operation to sync test */
	return 0;
}

int main(int argc, char **argv)
{
	int op, ret;

	opts = INIT_OPTS;
	opts.options = FT_OPT_SIZE | FT_OPT_RX_CNTR | FT_OPT_TX_CNTR;

	hints = fi_allocinfo();
	if (!hints)
		return EXIT_FAILURE;

	while ((op = getopt(argc, argv, "hBo:" ADDR_OPTS INFO_OPTS)) != -1) {
		switch (op) {
		case 'o':
			if (!strcmp(optarg, "readv")) {
				op_type = FT_RMA_READV;
			} else if (!strcmp(optarg, "writev")) {
				op_type = FT_RMA_WRITEV;
            } else if (!strcmp(optarg, "readmsg")) {
				op_type = FT_RMA_READMSG;
			} else if (!strcmp(optarg, "writemsg")) {
				op_type = FT_RMA_WRITEMSG;
			} else {
				ft_csusage(argv[0], NULL);
				fprintf(stderr, "  -o <op>\tselect operation type (read or write)\n");
				return EXIT_FAILURE;
			}
			break;
		default:
			ft_parse_addr_opts(op, optarg, &opts);
			ft_parseinfo(op, optarg, hints);
			break;
		case '?':
		case 'h':
			ft_usage(argv[0], "A vectored client-sever RMA example.");
			fprintf(stderr, "  -o <op>\trma op type: readv|writev (default: writev)]\n");
			return EXIT_FAILURE;
		}
	}

	if (optind < argc)
		opts.dst_addr = argv[optind];

	hints->ep_attr->type = FI_EP_RDM;
	hints->caps = FI_MSG | FI_RMA | FI_RMA_EVENT | FI_TAGGED | FI_SEND | FI_RECV;
    hints->mode = FI_CONTEXT/* | FI_LOCAL_MR*/;

	ret = run_test();

    fi_close((struct fid*)vmr);
    free(vbuf);

	ft_free_res();
	return -ret;
}
