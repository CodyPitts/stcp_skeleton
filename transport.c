/*
 * transport.c 
 *
 * COS461: Assignment 3 (STCP)
 *
 * This file implements the STCP layer that sits between the
 * mysocket and network layers. You are required to fill in the STCP
 * functionality in this file. 
 *
 */


#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <stdlib.h>
#include <assert.h>
#include <arpa/inet.h>
#include <algorithm>
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"

#define bit_win 3072

enum { CSTATE_ESTABLISHED, CSTATE_HANDSHAKING, CSTATE_CLOSING, CSTATE_CLOSED };    /* you should have more states */

/* this structure is global to a mysocket descriptor */
typedef struct
{
    bool_t done;    /*TRUE once connection is closed */

    int connection_state;   /* state of the connection (established, etc.) */
    tcp_seq initial_sequence_num;
    tcp_seq curr_sequence_num; //the current number to start from when sending
    tcp_seq last_ack_num_sent; //the last ack number we sent

    /* any other connection-wide global variables go here */
    tcp_seq congestion_win; //Congestion window
    tcp_seq recv_win;		  //our receive window: 3072
    tcp_seq send_win;		  //our send window: min(congestion window, their receive window) - (last byte sent - last byte ack'd)
    tcp_seq their_recv_win; //their receive window
    int* last_byte_sent;    //the last byte we have sent:current sequence# -1
    int* last_byte_ack;	  //the last byte ack'd by peer: the last th_ack -1

    tcphdr* hdr_buffer;
    char* data_buffer;
} context_t;

static void generate_initial_seq_num(context_t *ctx);
static void control_loop(mysocket_t sd, context_t *ctx);


/* initialise the transport layer, and start the main loop, handling
 * any data from the peer or the application.  this function should not
 * return until the connection is closed.
 */
void transport_init(mysocket_t sd, bool_t is_active)
{
    context_t *ctx;
    ctx = (context_t *) calloc(1, sizeof(context_t));
    assert(ctx);
    ctx->hdr_buffer = (tcphdr*)calloc(1,sizeof(tcphdr));
    assert(ctx->hdr_buffer);
    ctx->congestion_win = bit_win;
    ctx->recv_win = bit_win;
    ctx->send_win = bit_win;

    generate_initial_seq_num(ctx);
    ctx->curr_sequence_num = ctx->initial_sequence_num;

    ctx->last_byte_sent = (int*)calloc(1,sizeof(int));
    assert(ctx->last_byte_sent);
    ctx->last_byte_ack = (int*)calloc(1,sizeof(int));
    assert(ctx->last_byte_ack);
    *ctx->last_byte_sent = ctx->initial_sequence_num;
    *ctx->last_byte_ack = ctx->initial_sequence_num;

  
    /* XXX: you should send a SYN packet here if is_active, or wait for one
    * to arrive if !is_active.  after the handshake completes, unblock the
    * application with stcp_unblock_application(sd).  you may also use
    * this to communicate an error condition back to the application, e.g.
    * if connection fails; to do so, just set errno appropriately (e.g. to
    * ECONNREFUSED, etc.) before calling the function.
    */
    ctx -> connection_state = CSTATE_HANDSHAKING;
    if (is_active) {
    	//Creating SYN header to send
    	tcphdr *synhdr;
    	synhdr = (tcphdr *)calloc(1, sizeof(tcphdr));
    	assert(synhdr);
    	//Setting flags in header
    	synhdr->th_seq = htonl(ctx->curr_sequence_num);
    	synhdr->th_flags = TH_SYN;
    	synhdr->th_win = htons(bit_win);
    	//First handshake
    	if ((stcp_network_send(sd, synhdr, sizeof(tcphdr),NULL)) == -1){
    	   dprintf("Error: stcp_network_send()");
    	   exit(-1);
    	}
    	*(ctx->last_byte_sent) = ctx->curr_sequence_num; 
    	//Recieving from network requires setting the correct recv window
    	if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, ctx->recv_win))
    		== -1){
            dprintf("Error: stcp_network_recv()");
            exit(-1);
    	}

    	ctx->their_recv_win = ntohs(ctx->hdr_buffer->th_win);
    	ctx->send_win = std::min(ctx->their_recv_win, ctx->congestion_win);

    	//See if packet recv is the SYN_ACK packet
    	//Bitwise and to check for both the SYN flag and ACK flag
    	if (ctx->hdr_buffer->th_flags & (TH_SYN | TH_ACK)){
            //Check to see if peer's ack seq# is our SYN's seq# + 1
            //If so, send ACK in response
            if (ctx->hdr_buffer->th_ack == synhdr->th_seq + 1){
                *(ctx->last_byte_sent) = ctx->curr_sequence_num;
            	ctx->curr_sequence_num = ctx->hdr_buffer->th_ack;
            	*(ctx->last_byte_ack) = ctx->hdr_buffer->th_ack - 1; 

            	//Creating ACK header for last handshake
            	tcphdr *ackhdr;
            	ackhdr = (tcphdr *)calloc(1, sizeof(ackhdr));
            	assert(ackhdr);
            	ackhdr->th_ack = ctx->hdr_buffer->th_seq + 1;
            	ctx->last_ack_num_sent = ackhdr->th_ack;
            	ackhdr->th_flags = TH_ACK;
            	//Sliding window calculation
            	ctx->send_win = std::min(ctx->congestion_win, ctx->their_recv_win) - (ctx->last_byte_sent - ctx->last_byte_ack);
            	ackhdr->th_win = htons(bit_win);
        		if ((stcp_network_send(sd, ackhdr, sizeof(tcphdr),NULL)) == -1){
                    dprintf("Error: stcp_network_send()");
                    exit(-1);
        		}
                //If the ack number recieved is incorrect
            }
            else{
                dprintf("Error: ACK number incorrect");
                exit(-1);
            }
    	}
    	//Simultaneous syns sent
    	else if(ctx->hdr_buffer->th_flags & TH_SYN) {
            //Send SYN ACK, with our previous SEQ number, and their SEQ + 1
            tcphdr *synack;
            synack = (tcphdr*)calloc(1, sizeof(tcphdr));
            assert(synack);
            synack->th_seq = ctx->curr_sequence_num;
            synack->th_ack = ctx->hdr_buffer->th_seq+1;
            //Sliding window calculation 
            ctx->last_ack_num_sent = synack->th_ack;
            ctx->send_win = std::min(ctx->congestion_win, ctx->their_recv_win) - (ctx->last_byte_sent - ctx->last_byte_ack);

            synack->th_win = htons(bit_win);
            if ((stcp_network_send(sd, synack, sizeof(tcphdr), NULL)) == -1){
                dprintf("Error: stcp_network_send()");
                exit(-1);
            }

    	    //Wait on SYN ACK with our SEQ number +1 and their SEQ number again
    	    if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, ctx->recv_win))
                == -1){
                dprintf("Error: stcp_network_recv()");
                exit(-1);
            }
            //Check to see if SYN ACK
            if (ctx->hdr_buffer->th_flags & (TH_SYN | TH_ACK)){
    	  	    //check to see if ACK is  correct
    	  	    if (ctx->hdr_buffer->th_ack == synhdr->th_seq + 1){
                    *(ctx->last_byte_sent) = ctx->curr_sequence_num;
                    ctx->curr_sequence_num = ctx->hdr_buffer->th_ack;
                    *(ctx->last_byte_ack) = ctx->hdr_buffer->th_ack - 1;
                }
                //If ACK is incorrect
                else{
                    dprintf("Error: wrong Ack number");
                    exit(-1);
                }
            }
            //If not SYN ACK after simultaneous SYN's
            else {
                dprintf("Error: wrong flags");
                exit(-1);
            }
        }
    	//If not SYN ACK or SYN received
    	else {
            dprintf("Error: wrong flags");
            exit(-1);
    	}
    } 
    else{
        //Passively waiting for SYN
        if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, sizeof(tcphdr)))
            == -1){
        dprintf("Error: stcp_network_recv()");
        exit(-1);
        }
        ctx->their_recv_win = ntohs(ctx->hdr_buffer->th_win);
        ctx->hdr_buffer->th_seq = ntohl(ctx->hdr_buffer->th_seq);
        //Check for SYN flag
        if (ctx->hdr_buffer->th_flags & TH_SYN) {
            //Send a syn ack in response
            tcphdr *synack;
            synack = (tcphdr*)calloc(1, sizeof(synack));
            assert(synack);
            synack->th_seq = ctx->curr_sequence_num;
            synack->th_ack = ctx->hdr_buffer->th_seq + 1;
            synack->th_flags = (TH_SYN | TH_ACK);
            //Sliding window calculations
            ctx->last_ack_num_sent = synack->th_ack;
            ctx->send_win = std::min(ctx->congestion_win, ctx->their_recv_win) - (ctx->last_byte_sent - ctx->last_byte_ack);
            synack->th_win = htons(ctx->recv_win);
            if ((stcp_network_send(sd, synack, sizeof(tcphdr),NULL)) == -1){
                dprintf("Error: stcp_network_send()");
                exit(-1);
            }
            //Wait on ACK
            if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, sizeof(tcphdr)))
                == -1){
                dprintf("Error: stcp_network_recv()");
                exit(-1);
            }
            ctx->their_recv_win = ntohs(ctx->hdr_buffer->th_win);

            //Check for ACK flag and correct Ack Num
            if (!(ctx->hdr_buffer->th_flags & TH_ACK)
                || !(ctx->hdr_buffer->th_ack == ctx->curr_sequence_num+1)){
                dprintf("Error: Wrong ACK");
                exit(-1);
            } else {
                *(ctx->last_byte_ack)  = ctx->hdr_buffer->th_ack-1;

                *(ctx->last_byte_sent) = ctx->curr_sequence_num;
                ctx->curr_sequence_num = ctx->hdr_buffer->th_ack;
            }
        }
        //If Passively waiting and get a packet that isn't a SYN
        else {
            dprintf("Error: wrong flags");
            exit(-1);
        }
    }

    ctx->connection_state = CSTATE_ESTABLISHED;
    stcp_unblock_application(sd);

    control_loop(sd, ctx);
  
    /* do any cleanup here */
    free(ctx);
}


/* generate random initial sequence number for an STCP connection */
static void generate_initial_seq_num(context_t *ctx)
{
    assert(ctx);
  
#ifdef FIXED_INITNUM
    /* please don't change this! */
    ctx->initial_sequence_num = 1;
#else
    /* you have to fill this up */
    /*ctx->initial_sequence_num = RAND_NUM;*/
    srand(time(NULL));
    ctx->initial_sequence_num = rand() % 255;

#endif
}


/* control_loop() is the main STCP loop; it repeatedly waits for one of the
 * following to happen:
 *   - incoming data from the peer
 *   - new data from the application (via mywrite())
 *   - the socket to be closed (via myclose())
 *   - a timeout
 */
static void control_loop(mysocket_t sd, context_t *ctx)
{
    assert(ctx);
    assert(!ctx->done);
    assert(ctx->hdr_buffer);
    ctx->data_buffer = (char*)calloc(1, sizeof(char*));
    assert(ctx->data_buffer);
    timespec *abstime;
    abstime->tv_sec = 5;
    abstime->tv_nsec = 5000;
    bool finRecv = false;
    bool finSent = false;
    int max_send_window; 
    int data_in_flight;
		
    while (!ctx->done){
        unsigned int event;
	
        /* see stcp_api.h or stcp_api.c for details of this function */
        /* XXX: you will need to change some of these arguments! */
        if (finSent){
    		event = stcp_wait_for_event(sd, 0, abstime);
        }
        else{
        	event = stcp_wait_for_event(sd, 0, NULL);
        }
	 	if (event & TIMEOUT)
        {
            dprintf("Error: TIMEOUT");
            exit(-1);
        }
        /* check whether it was the network, app, or a close request */
        /*********************************APP_DATA***********************************/
        if ((event & APP_DATA) || ((event & ANY_EVENT) == (3 | 5 | 7))){	// handle event 1,3,5,7
            /* the application has requested that data be sent */
            /* see stcp_app_recv() */
            //Read data with stcp_app_recv(sd,dst,size) into dst as a char*
            //Sliding window calculations
            max_send_window = std::min(ctx->their_recv_win, ctx->congestion_win);
            data_in_flight = *(ctx->last_byte_sent) - *(ctx->last_byte_ack);
            //Get data from the app
            if (stcp_app_recv(sd, ctx->data_buffer, (max_send_window - data_in_flight) - 1) == (size_t)-1){
            	dprintf("Error: stcp_app_recv()");
            	exit(-1);
            }
            //Create packet with correct seq# and sending window
            tcphdr* datahdr;
            datahdr = (tcphdr*)calloc(1, sizeof(tcphdr));
            assert(datahdr);
            datahdr->th_seq = ctx->curr_sequence_num;
            //Send to network layer using stcp_network_send(sd, src, size, ...) as two packet(hdr, data)
            //Here need to convert multi byte data being sent with htons (dbuffer)

            datahdr->th_win = htons(bit_win);
            if (stcp_network_send(sd, datahdr, sizeof(datahdr), *(ctx->data_buffer), sizeof(*(ctx->data_buffer)), NULL) == -1){
            	dprintf("Error: stcp_network_send()");
            	exit(-1);
            }
            *(ctx->last_byte_sent) = ctx->curr_sequence_num + sizeof(*(ctx->data_buffer)) - 1;
            ctx->curr_sequence_num = *(ctx->last_byte_sent) + 1;
        }
        /********************************NETWORK_DATA**********************************/
        // handle 2,3,6,7
        if ((event & NETWORK_DATA) || ((event & ANY_EVENT) == (3 | 6 | 7)))
        {
            void* recvBuffer;
            size_t receivedData;
            tcp_seq recvSeqNum;
            tcp_seq lastRecvNum;
            int duplicateDataSize;
            int max_send_window = std::min(ctx->their_recv_win, ctx->congestion_win); 
            int data_in_flight = *(ctx->last_byte_sent) - *(ctx->last_byte_ack);
            recvBuffer = malloc(max_send_window - data_in_flight);
            receivedData = stcp_network_recv(sd, recvBuffer, (max_send_window - data_in_flight)) ;
            if (receivedData == (size_t)-1){
                dprintf("Error: stcp_network_recv()");
                exit(-1);
            }

		ctx->hdr_buffer = (struct tcphdr *) recvBuffer;
		size_t hdr_size = ((struct tcphdr *)recvBuffer)->th_off * sizeof(uint32_t);


		ctx->their_recv_win = ntohs(ctx->hdr_buffer->th_win);
		
		//*******************CHECK FOR FIN OR ACK ONLY HEADER**********************************
		if(receivedData == hdr_size)
		{	
			tcphdr *ackhdr;
			ackhdr = (tcphdr *)calloc(1, sizeof(ackhdr));
			assert(ackhdr);
			ackhdr->th_flags = TH_ACK;
			ackhdr->th_ack = ctx->hdr_buffer-> + 1;
			ctx ->last_ack_num_sent = ackhdr->th_ack;
			ackhdr->th_win = ctx->recv_win;

			//check if just an ACK, otherwise check flags and send an ACK if necessary
			if (ctx->hdr_buffer->th_flags & TH_ACK){
				*ctx->last_byte_ack = ctx->hdr_buffer->th_ack-1;
			}
			else if(ctx->hdr_buffer->th_flags  & (TH_FIN | TH_ACK))
			{
				*ctx->last_byte_ack = ctx->hdr_buffer->th_ack-1;
				finRecv = true;
				stcp_network_send(sd,ackhdr,sizeof(ackhdr));
			}
			else if (ctx->hdr_buffer->th_flags & TH_ACK){
				finRecv = true;
				stcp_network_send(sd,ackhdr,sizeof(ackhdr));
			}
		}
		//*******************RECIEVED A DATA PACKET **********************************
		else{
			//See if there was an ACK or FIN
			if(ctx->hdr_buffer->th_flags  & (TH_SYN | TH_ACK))
			{
				*ctx->last_byte_ack = ctx->hdr_buffer->th_ack-1;
				finRecv = true;
			}
			else if (ctx->hdr_buffer->th_flags & TH_ACK){
				*ctx->last_byte_ack = ctx->hdr_buffer->th_ack-1;
			}
			else if (ctx->hdr_buffer->th_flags & TH_ACK){
				finRecv = true;
			}

			recvSeqNum = ctx->hdr_buffer->th_seq;

			//Check to see if there was duplicate data
			if(recvSeqNum < ctx->last_ack_num_sent)
			{
				//Check to see if the duplicate data is large enough that it introduces new data
				if(recvSeqNum + (receivedData - hdr_size) > ctx-> last_ack_num_sent){
					duplicateDataSize = (ctx->last_ack_num_sent-1) - recvSeqNum;
					stcp_app_send(sd, recvBuffer+hdr_size + duplicateDataSize,receivedData - (hdr_size + duplicateDataSize));
					lastRecvNum = recvSeqNum + (receivedData - hdr_size);
				}
			}
			else
			{
				//If no duplicate data, pass everything up to the application
				stcp_app_send(sd, recvBuffer+hdr_size,receivedData - hdr_size);
				lastRecvNum = recvSeqNum + (receivedData - hdr_size);
			}

			//Send an ACK based on the data recieved
			tcphdr *ackhdr;
			ackhdr = (tcphdr *)calloc(1, sizeof(ackhdr));
			assert(ackhdr);
			ackhdr->th_flags = TH_ACK;
			ackhdr->th_ack = lastRecvNum + 1;
			ctx ->last_ack_num_sent = ackhdr->th_ack;
			ackhdr->th_win = ctx->recv_win;
			stcp_network_send(sd,ackhdr,sizeof(ackhdr));
		}
		//If we received a FIN, the peer no longer has anything to send us
		//ACK the FIN and wait on the app to give us everything
		if(finRecv)
		{
			stcp_fin_received(sd);
		}

	}
	/***********************************APP_CLOSE_REQUESTED*************************/
	//Handle 4,5,6,7
	if ((event & APP_CLOSE_REQUESTED) || ((event & ANY_EVENT) == (5 | 6 | 7)))
	{
		//Send FIN packet to network layer
		tcphdr* finhdr;
		finhdr = (tcphdr*)calloc(1, sizeof(tcphdr));
		assert(finhdr);
		finhdr->th_seq = htons(ctx->curr_sequence_num);
		finhdr->th_flags = TH_FIN;
		finhdr->th_win = ctx->recv_win;

		//send the header
		if (stcp_network_send(sd, finhdr, sizeof(finhdr),NULL) == -1){
			dprintf("Error: stcp_network_send()");
			exit(-1);
		}
		//increment by one because a FIN header is sent
		*(ctx->last_byte_sent)++;
    }

    if(finSent && finRecv)
	{
		ctx->done = true;
	}
}

/**********************************************************************/
/* dprintf
 *
 * Send a formatted message to stdout.
 * 
 * format               A printf-style format string.
 *
 * This function is equivalent to a printf, but may be
 * changed to log errors to a file if desired.
 *
 * Calls to this function are generated by the dprintf amd
 * dperror macros in transport.h
 */
void our_dprintf(const char *format,...)
{
    va_list argptr;
    char buffer[1024];

    assert(format);
    va_start(argptr, format);
    vsnprintf(buffer, sizeof(buffer), format, argptr);
    va_end(argptr);
    fputs(buffer, stdout);
    fflush(stdout);
}



