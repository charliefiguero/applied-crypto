/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include <stdio.h>
#include "helloworld.h"

int main(int argc, char *argv[])
{
	// select a configuration st. the external 16 MHz oscillator is used
	scale_conf_t scale_conf = {
		.clock_type = SCALE_CLOCK_TYPE_EXT,
		.clock_freq_source = SCALE_CLOCK_FREQ_16MHZ,
		.clock_freq_target = SCALE_CLOCK_FREQ_16MHZ,

		.tsc = false};

	// initialise the development board
	if (!scale_init(&scale_conf)) { return -1; }

	// char x[] = "hello world";

	while (true)
	{
		// read  the GPI pin, and hence switch : t   <- GPI
		bool t = scale_gpio_rd(SCALE_GPIO_PIN_GPI);
		// write the GPO pin, and hence LED    : GPO <- t
		scale_gpio_wr(SCALE_GPIO_PIN_GPO, t);

		// write the trigger pin, and hence LED    : TRG <- 1 (positive edge)
		scale_gpio_wr(SCALE_GPIO_PIN_TRG, true);
		// delay for 500 ms = 1/2 s
		scale_delay_ms(500);
		// write the trigger pin, and hence LED    : TRG <- 0 (negative edge)
		scale_gpio_wr(SCALE_GPIO_PIN_TRG, false);
		// delay for 500 ms = 1/2 s
		scale_delay_ms(500);

		// int n = strlen( x );

		// write x = "hello world" to the UART
		// for( int i = 0; i < n; i++ ) {
		//   scale_uart_wr( SCALE_UART_MODE_BLOCKING, x[ i ] );
		// }

		uint8_t data[100];

		printout("about to try to read:", 21);
		int size = octetstr_rd(data, 2);
		if ( size == -1 ) printout( "couldnt read: returned -1.", 26);

		if (size != -1)
		{
			printout("about to write:", 14);
			octetstr_wr(data, size);
		}
	}

	return 0;
}

// read an octet string from the UART, #include <stdlib.h>
// decoding it into a byte sequencer of maximum length n_r
int octetstr_rd(uint8_t *r, int n_r)
{
	//if (!scale_uart_rd_avail()) { return -1; }
	printout("ready to read:", 14);	

	// read in first 3 chars
	uint8_t prefix0 = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
	uint8_t prefix1 = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
	uint8_t colon = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
	printout("",0);

	if ( colon != ':' ) {
		printout("", 0);
		printout("no colon input.", 16);
		return -1;	
	}

	// calculate size
	uint8_t size = hex_to_int(prefix0) * 16 + hex_to_int(prefix1);

	// test int_to_hex...
	uint8_t hexarr[2] = {48,48};
	int_to_hex(size, hexarr);
	
	uint8_t i0, i1;
	for ( int i = 0; i < size; i++ ) {
		i0 = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
		i1 = scale_uart_rd(SCALE_UART_MODE_BLOCKING);
		r[i] = (hex_to_int(i0) * 16) + hex_to_int(i1);
	}
	printout("", 0);
	for ( int i = 0; i < size; i++ ) {
		uint8_t tmp[2] = {48, 48};
		int_to_hex(r[i], tmp);
		scale_uart_wr( SCALE_UART_MODE_BLOCKING, tmp[0] );
		scale_uart_wr( SCALE_UART_MODE_BLOCKING, tmp[1] );
	}
	printout("", 0);
	printout("finished reading", 16);
	return (int) size;
}

void printout( char* message, int size ) {
	for ( int i = 0; i < size; i++ ) {
		scale_uart_wr( SCALE_UART_MODE_BLOCKING, (uint8_t) message[i] );
	}
	scale_uart_wr( SCALE_UART_MODE_BLOCKING, '\r' );
	//scale_uart_wr( SCALE_UART_MODE_BLOCKING, '\n' );
}

// write an octet string to the UART. encoding it from a byte sequencexofgiven lengthn_x.
void octetstr_wr(const uint8_t *x, int n_x)
{
	//if (!scale_uart_wr_avail()) { return; }
	uint8_t hex[2] = {48, 48};

	// calculate and write prefix
	int_to_hex(n_x, hex);
	scale_uart_wr( SCALE_UART_MODE_BLOCKING, hex[0] );
	scale_uart_wr( SCALE_UART_MODE_BLOCKING, hex[1] );
	scale_uart_wr( SCALE_UART_MODE_BLOCKING, ':' );
	printout("", 0);
	
	for (int i = 0; i < n_x; i++)
	{ 
		uint8_t tmp[2] = {48, 48};
		int_to_hex(x[i], tmp);
		scale_uart_wr( SCALE_UART_MODE_BLOCKING, tmp[0] );
		scale_uart_wr( SCALE_UART_MODE_BLOCKING, tmp[1] );
	}
	printout("", 0);
}

uint8_t hex_to_int(uint8_t hex) {
	uint8_t decimal = 0;
	switch ( hex ) {
		case '0' : 
			decimal = 0;
			break;
		case '1' : 
			decimal = ( 1 ); 
			break;
		case '2' : 
			decimal = ( 2 );
			break;
		case '3' : 
			decimal = ( 3 );
			break;
		case '4' : 
			decimal = ( 4 ); 
			break;
		case '5' : 
			decimal = ( 5 );
			break;
		case '6' : 
			decimal = ( 6 ); 
			break;
		case '7' : 
			decimal = ( 7 );
			break; 
		case '8' : 
			decimal = ( 8 ); 
			break;
		case '9' : 
			decimal = ( 9 ); 
			break;
		case 'A' : 
			decimal = ( 10 ); 
			break;
		case 'B' : 
			decimal = ( 11 );
			break; 
		case 'C' : 
			decimal = ( 12 ); 
			break;
		case 'D' : 
			decimal = ( 13 );
			break; 
		case 'E' : 
			decimal = ( 14 ); 
			break;
		case 'F' : 
			decimal = ( 15 );
			break; 
	}
	return decimal;
}

// hex must be an array size 2
void int_to_hex(uint8_t decimal, uint8_t hex[2] ) {
	uint8_t quotient, remainder;
	int i = 0;

	quotient = decimal;
	 
	while (quotient != 0)
	{
		remainder = quotient % 16;
		if (remainder < 10) hex[1-i] = '0' + remainder;
		else {
			hex[1-i] = 'A' - 10 + remainder;
		}
		quotient = quotient / 16;
		i++;	
	}
}
