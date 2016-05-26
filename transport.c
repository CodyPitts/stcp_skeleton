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
  bool_t done;    /* TRUE once connection is closed */
  
  int connection_state;   /* state of the connection (established, etc.) */
  tcp_seq initial_sequence_num;
  tcp_seq curr_sequence_num;
  tcp_seq curr_ack_num;
  
  /* any other connection-wide global variables go here */
  tcp_seq congestion_win, recv_win, send_win;
  int* last_byte_sent;
  int* last_byte_ack;

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
  
  /* XXX: you should send a SYN packet here if is_active, or wait for one
   * to arrive if !is_active.  after the handshake completes, unblock the
   * application with stcp_unblock_application(sd).  you may also use
   * this to communicate an error condition back to the application, e.g.
   * if connection fails; to do so, just set errno appropriately (e.g. to
   * ECONNREFUSED, etc.) before calling the function.
   */
  ctx -> connection_state = CSTATE_HANDSHAKING;
  //KEEP TRACK OF ACK AND SEQ #s
  if (is_active) {
	// creating SYN header to send
	tcphdr *synhdr;
	synhdr = (tcphdr *)calloc(1, sizeof(tcphdr));
	assert(synhdr);
	// Setting flags in header
	synhdr->th_seq = ctx->curr_sequence_num;
	synhdr->th_flags = TH_SYN;
	synhdr->th_win = htons(bit_win); //CODY: wrote syn instead of synhdr (FIXED)
	// First handshake
	// maybe synhdr->th_win instead of sizeof(...)
	if ((stcp_network_send(sd, synhdr, sizeof(tcphdr),NULL)) == -1){
	  dprintf("Error: stcp_network_send()"); //CODY: call with dprintf, not our_dprintf (FIXED)
	  exit(-1);
	}
	*(ctx->last_byte_sent) = ctx->curr_sequence_num + 1; 
	// Recieving from network requires setting the correct recv window
	if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, ctx->recv_win))
		== -1){
	  dprintf("Error: stcp_network_recv()");
	  exit(-1);
	}
	ctx->recv_win = ntohs(ctx->hdr_buffer->th_win);
	// See if packet recv is the SYN_ACK packet
	// Bitwise and to check for both the SYN flag and ACK flag
	if (ctx->hdr_buffer->th_flags & (TH_SYN | TH_ACK)){
		 // Check to see if peer's ack seq# is our SYN's seq# + 1
	  if (ctx->hdr_buffer->th_ack == synhdr->th_seq + 1){
		ctx->curr_sequence_num = ctx->hdr_buffer->th_ack;
		// creating ACK header for last handshake
		tcphdr *ackhdr;
		ackhdr = (tcphdr *)calloc(1, sizeof(ackhdr));
		assert(ackhdr);
		ackhdr->th_ack = ntohs(ctx->hdr_buffer->th_seq + 1);
		ctx->curr_ack_num = ackhdr->th_ack;
		ackhdr->th_flags = TH_ACK;
		*(ctx->last_byte_ack) = ackhdr->th_ack; //CODY: tcp_seq to pointer (FIXED)
		// Sliding window calculation
		ctx->send_win = std::min(ctx->congestion_win, ctx->recv_win) - (ctx->last_byte_sent - ctx->last_byte_ack);
		ackhdr->th_win = htons(bit_win);
		if ((stcp_network_send(sd, ackhdr, sizeof(tcphdr),NULL)) == -1){
		  dprintf("Error: stcp_network_send()");
		  exit(-1);
		}
		*(ctx->last_byte_sent) = ctx->curr_sequence_num + 1;
	  }
	}
	//simultaneous syns sent
	else if(ctx->hdr_buffer->th_flags & TH_SYN) {
	  //send SYN ACK, with our previous SEQ number, and their SEQ + 1
	  //Wait on SYN ACK with our SEQ number +1 and their SEQ number again
	  tcphdr *synack;
	  synack = (tcphdr*)calloc(1, sizeof(tcphdr));
	  assert(synack);
	  synack->th_seq = ctx->curr_sequence_num;
	  synack->th_ack = ntohs(ctx->hdr_buffer->th_seq)+1;
	  // Sliding window calculation maybe
	  ctx->curr_ack_num = synack->th_ack;
	  ctx->send_win = std::min(ctx->congestion_win, ctx->recv_win) + ctx->last_byte_sent - ctx->last_byte_ack + 1;

	  synack->th_win = htons(bit_win);
	  if ((stcp_network_send(sd, synack, sizeof(tcphdr), NULL)) == -1){
		dprintf("Error: stcp_network_send()");
		exit(-1);
	  }
	  *(ctx->last_byte_sent) = sizeof(tcphdr) + ctx->curr_sequence_num;
	}
	//wrong flags
	else {
	  dprintf("Error: wrong flags");
	  exit(-1);
	}
  } else {
	  // Passively waiting for syn
	if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, sizeof(tcphdr)))
		== -1){
	  dprintf("Error: stcp_network_recv()");
	  exit(-1);
	}
	ctx->recv_win = ntohs(ctx->hdr_buffer->th_win);
	if (ctx->hdr_buffer->th_flags & TH_SYN) {
	  //send SYN ACK, with our previous SEQ number, and their SEQ + 1
	  //Wait on SYN ACK with our SEQ number +1 and their SEQ number again
	  tcphdr *synack;
	  synack = (tcphdr*)calloc(1, sizeof(synack));
	  assert(synack);
	  synack->th_seq = ctx->curr_sequence_num;
	  synack->th_ack = ntohs(ctx->hdr_buffer->th_seq)++; //CODY: ACK NOT CORRECTLY CALCULATED
	  // Sliding window calculations
	  ctx->curr_ack_num = synack->th_ack;
	  ctx->recv_win = bit_win + ctx->last_byte_ack - ctx->last_byte_sent + 1;
	  ctx->send_win = std::min(ctx->congestion_win, ctx->recv_win);
	  synack->th_win = htons(ctx->send_win);
	  if ((stcp_network_send(sd, synack, sizeof(tcphdr),NULL)) == -1){
		dprintf("Error: stcp_network_send()");
		exit(-1);
	  }
	  *(ctx->last_byte_sent) = sizeof(tcphdr) + ctx->curr_sequence_num;
	  if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, sizeof(tcphdr)))
		  == -1){
		dprintf("Error: stcp_network_recv()");
		exit(-1);
	  }
	  ctx->recv_win = ntohs(ctx->hdr_buffer->th_win);
	  // Wait on ACK
	  if (!(ctx->hdr_buffer->th_flags & TH_ACK)
		  || !(ctx->hdr_buffer->th_seq == ctx->curr_sequence_num+1)){
		dprintf("Error: Wrong ACK");
		exit(-1);
	  } else {
		  ctx->curr_ack_num = ntohs(ctx->hdr_buffer->th_seq)+1;
	  }
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
  ctx->curr_sequence_num = ctx->initial_sequence_num;
  *(ctx->last_byte_sent) = ctx->initial_sequence_num;
  *(ctx->last_byte_ack) = ctx->initial_sequence_num;
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
  
  while (!ctx->done){
	unsigned int event;
	
	/* see stcp_api.h or stcp_api.c for details of this function */
	/* XXX: you will need to change some of these arguments! */
	event = stcp_wait_for_event(sd, 0, NULL);
	
	if (event & TIMEOUT)
	{
		dprintf("Error: TIMEOUT");
		exit(-1);
	}
	/* check whether it was the network, app, or a close request */
	/*********************************APP_DATA***********************************/
	if ((event & APP_DATA) || ((event & ANY_EVENT) == 3 | 5 | 7)){	// handle event 1,3,5,7 CODY: parenthesis issue? bitwise stuff
	  /* the application has requested that data be sent */
	  /* see stcp_app_recv() */
		//read data with stcp_app_recv(sd,dst,size) into dst as a char*
		//  read data with stcp_app_recv(sd,dst,size) into dst as a char*
		// Sliding window calculations
		int max_send_window = std::min(ctx->hdr_buffer->th_win, ctx->congestion_win); //CODY: error: no matching function for call to 'min(uint16_t&, tcp_seq&)'
		int data_in_flight = *(ctx->last_byte_sent) - *(ctx->last_byte_ack);
		if (stcp_app_recv(sd, ctx->data_buffer, (max_send_window - data_in_flight) - 1) == -1){
			dprintf("Error: stcp_app_recv()");
			exit(-1);
		}
		// Create packet with correct seq# and sending window
		tcphdr* datahdr;
		datahdr = (tcphdr*)calloc(1, sizeof(tcphdr));
		assert(datahdr);
		datahdr->th_seq = ctx->curr_sequence_num;
		// Send to network layer using stcp_network_send(sd, src, size, ...) as two packet(hdr, data)
		//Here need to convert multi byte data being sent with htons (dbuffer)

		datahdr->th_win = htons(bit_win);   
		if (stcp_network_send(sd, datahdr, sizeof(datahdr), *(ctx->data_buffer), sizeof(*(ctx->data_buffer)), NULL) == -1){ //CODY: not sure of changes I made here
			dprintf("Error: stcp_network_send()");
			exit(-1);
		}
		*(ctx->last_byte_sent) = ctx->curr_sequence_num+sizeof(datahdr)+sizeof(*(ctx->data_buffer)); //CODY: rewrite this line
	}
	/********************************NETWORK_DATA**********************************/
	// handle 2,3,6,7
	if ((event & NETWORK_DATA) || ((event & ANY_EVENT) == 3 | 6 | 7))
	{
		// Read in packet hdr from network
		//We receive the packet but it probably needs to go to ntohs
		if (stcp_network_recv(sd, ctx->hdr_buffer, sizeof(ctx->hdr_buffer)) == -1){
			dprintf("Error: stcp_network_recv()");
			exit(-1);
		}
		ctx->recv_win = ntohs(ctx->hdr_buffer->th_win);
		//*******************RECIEVED AN ACK PACKET **********************************
		if (ctx->hdr_buffer->th_flags & TH_ACK){
			if (stcp_network_recv(sd, ctx->data_buffer, sizeof(ctx->data_buffer)) == -1){
				dprintf("Error: stcp_network_recv()");
				exit(-1);
			}
			ctx->recv_win = ntohs(ctx->hdr_buffer->th_win);
		}
		//****************RECIEVED A FIN PACKET *******************************************
		else if (ctx->hdr_buffer->th_flags & TH_FIN)
		{
			// Send FIN ACK packet to network layer
			tcphdr* finack;
			finack = (tcphdr*)calloc(1, sizeof(tcphdr));
			assert(finack);
			finack->th_seq = ctx->curr_sequence_num;
			finack->th_ack = ntohs(ctx->hdr_buffer->th_seq)++; //CODY: ACK NOT CORRECTLY CALCULATED
			finack->th_flags = TH_FIN & TH_ACK;
			// window stuff
			//Since we're sending to the network we'll need to htons
			if (stcp_network_send(sd, finack, sizeof(finack), NULL) == -1){
				dprintf("Error: stcp_network_send()");
				exit(-1);
			}
			*(ctx->last_byte_sent) = sizeof(finack) + ctx->curr_sequence_num;
			stcp_fin_received(sd);
		}
		//******************RECIEVED A HEADER PACKET WITH NO FLAGS ONLY DATA*********************
		else if (!ctx->hdr_buffer->th_flags){
			//recv data
			if (stcp_network_recv(sd, ctx->data_buffer, sizeof(ctx->data_buffer)) == -1){
				dprintf("Error: stcp_network_recv()");
				exit(-1);
			}
			ctx->recv_win = ntohs(ctx->hdr_buffer->th_win);

		}

		// Pass data to application layer
		stcp_app_send(sd, ctx->data_buffer, sizeof(ctx->data_buffer));
	}
	/***********************************APP_CLOSE_REQUESTED*************************/
	// handle 4,5,6,7
	if ((event & APP_CLOSE_REQUESTED) || ((event & ANY_EVENT) == 5 | 6 | 7))
	{
		// Send FIN packet to network layer
		tcphdr* finhdr;
		finhdr = (tcphdr*)calloc(1, sizeof(tcphdr));
		assert(finhdr);
		finhdr->th_seq = ctx->curr_sequence_num;
		finhdr->th_flags = TH_FIN;
		// window stuff
		//Since we're sending to the network we'll need to htons
		if (stcp_network_send(sd, finhdr, sizeof(finhdr),NULL) == -1){
			dprintf("Error: stcp_network_send()");
			exit(-1);
		}
		*(ctx->last_byte_sent) = sizeof(finhdr);
		//start a timer for timeout on ack received
		//gettimeofday(2)
		//somehow check for timeout while waiting on network recv
		//if timeout stcp_fin_received
		event = stcp_wait_for_event(sd, 0, 5); //CODY: invalid conversion from ‘int’ to ‘const timespec*

		if (event & NETWORK_DATA){
			// Recv ACK for sent FIN packet
			//After we receive we want to ntohs
			//While loop, wait for all data from peer, checking for FIN
			if (stcp_network_recv(sd, ctx->hdr_buffer, sizeof(ctx->hdr_buffer)) == -1){
				dprintf("Error: stcp_network_recv()");
				exit(-1);
			}
			ctx->recv_win = ntohs(ctx->hdr_buffer->th_win);

			tcphdr *ackhdr;
			ackhdr = (tcphdr *)calloc(1, sizeof(ackhdr));
			assert(ackhdr);
			ackhdr->th_ack = ctx->hdr_buffer->th_seq + 1;
			ackhdr->th_flags = TH_ACK;
			//Send
			if ((stcp_network_send(sd, ackhdr, sizeof(tcphdr), NULL)) == -1){
				dprintf("Error: stcp_network_send()");
				exit(-1);
			}
		}
		else if (event & TIMEOUT)
		{
			dprintf("Error: TIMEOUT");
			exit(-1);
		}
		// Close down the application layer
		stcp_fin_received(sd);
	}
	/*********************************TIMEOUT******************************************/
	/* etc. */
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
void dprintf(const char *format,...)
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



