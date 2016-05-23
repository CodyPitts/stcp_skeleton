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
#include "mysock.h"
#include "stcp_api.h"
#include "transport.h"


enum { CSTATE_ESTABLISHED, CSTATE_HANDSHAKING, CSTATE_CLOSING, CSTATE_CLOSED };    /* you should have more states */


/* this structure is global to a mysocket descriptor */
typedef struct
{
  bool_t done;    /* TRUE once connection is closed */
  
  int connection_state;   /* state of the connection (established, etc.) */
  tcp_seq initial_sequence_num;
  tcp_seq curr_sequence_num;
  
  /* any other connection-wide global variables go here */
  tcp_seq byteWindow = 3072;
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
	// creating SYN header
	tcphdr *synhdr;
	synhdr = (tcphdr *)calloc(1, sizeof(tcphdr));
	assert(synhdr);
	// Setting flags in header
	synhdr->th_seq = ctx->curr_sequence_num;
	synhdr->th_flags = TH_SYN;
	// First handshake
	// maybe synhdr->th_win instead of sizeof(...)
	if ((stcp_network_send(sd, synhdr, sizeof(tcphdr),NULL)) == -1){
	  //close_connection();
	}
	// Recieving from network requires setting the correct recv window
	if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, sizeof(tcphdr)))
		== -1){
	  //close_connection();
	}
	// See if packet recv is the SYN_ACK packet
	// Bitwise and to check for both the SYN flag and ACK flag
	if (ctx->hdr_buffer->th_flags & (TH_SYN | TH_ACK)){
	  // Check to see if peer's ack seq# is + 1 our SYN's seq#
	  if (ctx->hdr_buffer->th_ack == synhdr->th_seq + 1){
		ctx->curr_sequence_num++;
		// creating ACK header for last handshake
		tcphdr *ackhdr;
		ackhdr = (tcphdr *)calloc(1, sizeof(ackhdr));
		assert(ackhdr);
		ackhdr->th_ack = ctx->hdr_buffer->th_seq+1;
		ackhdr->th_flags = TH_ACK;
		if ((stcp_network_send(sd, ackhdr, sizeof(tcphdr),NULL)) == -1){
		  //close_connection();
		}
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
	  synack->th_ack = ctx->hdr_buffer->th_seq++;
	  if ((stcp_network_send(sd, synack, sizeof(tcphdr),NULL)) == -1){
		//close_connection();
	  }
	}
	//wrong flags
	else {
	  //close_connection();
	}
  } else {
	if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, sizeof(tcphdr)))
		== -1){
	  //close_connection();
	}
	if (ctx->hdr_buffer->th_flags & TH_SYN) {
	  //send SYN ACK, with our previous SEQ number, and their SEQ + 1
	  //Wait on SYN ACK with our SEQ number +1 and their SEQ number again
	  tcphdr *synack;
	  synack = (tcphdr*)calloc(1, sizeof(synack));
	  assert(synack);
	  synack->th_seq = ctx->curr_sequence_num;
	  synack->th_ack = ctx->hdr_buffer->th_seq++;
	  if ((stcp_network_send(sd, synack, sizeof(tcphdr),NULL)) == -1){
		//close_connection();
	  }
	  if ((stcp_network_recv(sd, (void*)ctx->hdr_buffer, sizeof(tcphdr)))
		  == -1){
		//close_connection();
	  }
	  if (!(ctx->hdr_buffer->th_flags & TH_ACK)
		  || !(ctx->hdr_buffer->th_seq == ctx->curr_sequence_num+1)){
		// close_connection();
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
  asser(ctx - data_buffer);
  
  while (!ctx->done){
	unsigned int event;
	
	/* see stcp_api.h or stcp_api.c for details of this function */
	/* XXX: you will need to change some of these arguments! */
	event = stcp_wait_for_event(sd, 0, NULL);
	
	/* check whether it was the network, app, or a close request */
	/*********************************APP_DATA***********************************/
	if ((event & APP_DATA) || ((event & ANY_EVENT) == 3 | 5 | 7)){	// handle event 1,3,5,7
	  /* the application has requested that data be sent */
	  /* see stcp_app_recv() */
		//  read data with stcp_app_recv(sd,dst,size) into dst as a char*
		if (stcp_app_recv(sd, data_buffer, 3072) == -1)
		{
			//close_connection();
		}
		// Create packet with correct seq# and sending window
		tcphdr* datahdr;
		datahdr = (tcphdr*)calloc(1, sizeof(tcphdr));
		assert(datahdr);
		ctx->datahdr->th_seq = curr_sequence_num;
		//datahdr->th_win = 3072-sizeof(data_buffer)-1;   // Sliding window calculations
		// Send to network layer using stcp_network_send(sd, src, size, ...) as two packet(hdr, data)
		if (stcp_network_send(sd, datahdr, sizeof(datahdr), data_buffer, sizeof(data_buffer), NULL) == -1)
		{
			// 	close_connection();
		}
		// Recv ACK
		if (stcp_network_recv(sd, ctx->hdr_buffer, sizeof(ctx->hdr_buffer)) == -1)
		{
			//close_connection();
		}
		// Check for ACK
		if (!(ctx->hdr_buffer->th_flags & TH_ACK))
		{
			// No ACK
		}

	}
	/********************************NETWORK_DATA**********************************/
	// handle 2,3,6,7
	if ((event & NETWORK_DATA) || ((event & ANY_EVENT) == 3 | 6 | 7))
	{
		// Read in packet hdr from network
		if (stcp_network_recv(sd, ctx->hdr_buffer, sizeof(ctx->hdr_buffer)) == -1)
		{
			// close_connection();
		}
		// crazy flag check or not
		if (ctx->hdr_buffer->th_flags )
		{
			// flag stuff
		}
		// Read in data from network
		if (stp_network_recv(sd, ctx->data_buffer, sizeof(ctx->data_buffer)) == -1)
		{
			//close_connection();
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
		finhdr->th_seq = curr_sequence_num;
		finhdr->th_flags = TH_FIN;
		// window stuff
		if (stcp_network_send(sd, finhdr, sizeof(finhdr),NULL) == -1)
		{
			//close_connection();
		}
		// Recv ACK for sent FIN packet
		if (stcp_network_recv(sd, ctx->hdr_buffer, sizeof(ctx->hdr_buffer)) == -1)
		{
			//close_connection();
		}
		// Check ACK
		if (ctx->hdr_buffer->th_flags & TH_FIN)
		{
			// yay ACK flag recieve FIN
			// add timeout stuff
			if (stcp_network_recv(sd, ctx->hdr_buffer, sizeof(ctx->hdr_buffer)) == -1)
			{
				//close_connection();
			}
			tcphdr *ackhdr;
			ackhdr = (tcphdr *)calloc(1, sizeof(ackhdr));
			assert(ackhdr);
			ackhdr->th_ack = ctx->hdr_buffer->th_seq + 1;
			ackhdr->th_flags = TH_ACK;
			if ((stcp_network_send(sd, ackhdr, sizeof(tcphdr), NULL)) == -1){
				//close_connection();
			}
		}
		// Close down the application layer
		stcp_fin_recieved(sd);
	}
	/* etc. */
  }
}


/**********************************************************************/
/* our_dprintf
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



