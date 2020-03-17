/* Copyright (C) 2018 Daniel Page <csdsp@bristol.ac.uk>
 *
 * Use of this source code is restricted per the CC BY-NC-ND license, a copy of
 * which can be found via http://creativecommons.org (and should be included as
 * LICENSE.txt within the associated archive or repository).
 */

#include <stdio.h>
#include "helloworld.h"

int main( int argc, char* argv[] ) {
  // select a configuration st. the external 16 MHz oscillator is used
  scale_conf_t scale_conf = {
    .clock_type        = SCALE_CLOCK_TYPE_EXT,
    .clock_freq_source = SCALE_CLOCK_FREQ_16MHZ,
    .clock_freq_target = SCALE_CLOCK_FREQ_16MHZ,

    .tsc               = false
  };

  // initialise the development board
  if( !scale_init( &scale_conf ) ) {
    return -1;
  }

  // char x[] = "hello world";

  while( true ) {
    // read  the GPI     pin, and hence switch : t   <- GPI
    bool t = scale_gpio_rd( SCALE_GPIO_PIN_GPI        );
    // write the GPO     pin, and hence LED    : GPO <- t
             scale_gpio_wr( SCALE_GPIO_PIN_GPO, t     );

    // write the trigger pin, and hence LED    : TRG <- 1 (positive edge)
             scale_gpio_wr( SCALE_GPIO_PIN_TRG, true  );
    // delay for 500 ms = 1/2 s
    scale_delay_ms( 500 );
    // write the trigger pin, and hence LED    : TRG <- 0 (negative edge)
             scale_gpio_wr( SCALE_GPIO_PIN_TRG, false );
    // delay for 500 ms = 1/2 s
    scale_delay_ms( 500 );

    // int n = strlen( x );

    // write x = "hello world" to the UART
    // for( int i = 0; i < n; i++ ) {
    //   scale_uart_wr( SCALE_UART_MODE_BLOCKING, x[ i ] );
    // }

    uint8_t data[10];
    uint8_t *r = data;

    int size = octetstr_rd(r, 10);
    if ( size != -1 ) { octetstr_wr( r, size ); }
  }

  return 0;
}

// read an octet string from the UART, #include <stdlib.h>
// decoding it into a byte sequencer of maximum length n_r
int octetstr_rd( uint8_t* r, int n_r ) {
    int size = 0;
    bool returned = false;

    if( !scale_uart_rd_avail() ) {
        return -1;
    }
    while (size < n_r) {
        while(!scale_uart_rd_avail()){}
        r[size] = scale_uart_rd( SCALE_UART_MODE_BLOCKING );
        size++;
        if (r[size] == 'a') {
            returned = true;
            break;
        }
    }
    if ( !returned ) {
        return n_r;
    }

    return size;
}

// write an octet string to the UART. encoding it from a byte sequencexofgiven lengthn_x.
void octetstr_wr( const uint8_t* x, int n_x ) {
    if (!scale_uart_wr_avail()) { return; }
    for (int i = 0; i < n_x; i++) {
        scale_uart_wr(SCALE_UART_MODE_BLOCKING, x[i]);
    }
}
