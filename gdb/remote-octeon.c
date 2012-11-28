/* Remote protocol for Octeon Simple Executive cross debugger. 

   Copyright (C) 2004, 2005, 2006 Cavium Networks.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 2 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program; if not, write to the Free Software
   Foundation, Inc., 51 Franklin Street, Fifth Floor,
   Boston, MA 02110-1301, USA.  */

#include "defs.h"
#include "gdbcore.h"
#include "gdbarch.h"
#include "inferior.h"
#include "target.h"
#include "value.h"
#include "command.h"
#include "gdb_string.h"
#include "exceptions.h"
#include "gdbcmd.h"
#include <sys/types.h>
#include "serial.h"
#include "symfile.h"
#include "regcache.h"
#include <time.h>
#include <ctype.h>
#include <signal.h>
#include "top.h"
#include "mips-tdep.h"
#include "gdb_assert.h"
#include "cli/cli-decode.h"  /* struct cmd_list_element is defined. */
#include <sys/wait.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "gdbthread.h"

/* Define the target subroutine names. */
struct target_ops octeon_ops, octeon_pci_ops;

extern void set_resumed_once (void);
/* Local function declarations */
static void close_connection ();
static void create_connection ();
static void simulator_fork (char **);
static void agent_fork (char **);
static int gets_octeondebug (char *);
static void octeon_close (int);
static void octeon_interrupt (int);
static void octeon_interrupt_twice (int);
static void process_core_command (char *, int, struct cmd_list_element *c);
static void show_core_command (struct ui_file *, int, 
			       struct cmd_list_element *, const char *);
static void process_mask_command (char *, int, struct cmd_list_element *c);
static void process_stepmode_command (char *, int, struct cmd_list_element *c);
static void process_step_isr_command (char *, int, struct cmd_list_element *c);
static void octeon_stop (ptid_t ptid);
static void get_core_mask (void);
static int set_focus (int);
static void get_focus (void);
static int set_step_all (int);
static int set_step_isr (int);
static int puts_octeondebug (char *);
static int readchar (int);
static int send_command_get_int_reply_generic (char *, char *, int);
static void set_performance_counter0_event (char *, int, 
					    struct cmd_list_element *c);
static void set_performance_counter1_event (char *, int, 
					    struct cmd_list_element *c);
static void show_performance_counter0_event_and_counter
(struct ui_file *, int, struct cmd_list_element *, const char *);
static void show_performance_counter1_event_and_counter
(struct ui_file *, int, struct cmd_list_element *, const char *);
static void octeon_resume (struct target_ops *ops, ptid_t ptid, int step, enum target_signal sigal);

/* Send ^C to target to halt it.  Target will respond, and send us a packet. */
static void (*ofunc) (int);
static int octeon_control_c_hit;
static jmp_buf octeon_jmp_buf;

/* The focused core and is set in set_focus(). */
static int octeon_coreid = -1;
/* Controls stepping, single core or all the cores. */
static int octeon_stepmode = 0;
/* Controls single stepping behavior for ISR. */
static int octeon_stepisr = 1;
/* The string of cores separated by comma set for debugging. For ex.:
   0,3,4.  */
static char *mask_cores = NULL;
/* The mask of the cores that are enabled for debugging.  */
static unsigned octeon_activecores = 0;
/* Controls spawning the simulator. */
static int octeon_spawn_sim = 0;
/* With spawn-sim, it controls whether to display the simulator in an
   xterm or to run it in the background with its output
   suppressed.  */
static int octeon_display_sim = 1;
/* Performance counters event.  */
static char *perf_event[2] = {0, 0};

static struct serial *octeon_desc;
/* Initially load 512 bytes of memory from the debug stub. For the subsequent
   memory read operation, if the memory address is within this 512 bytes then
   return the value from cache_mem_data instead of asking from debug stub.
   Sending packets to and fro from debug stub slows down a lot.  */
static CORE_ADDR cache_mem_addr = 0;
static char cache_mem_data[512];  /* This size has to be a power of 2.  */

/* The max size of buffer that is used for sending packet to the debug
   stub. Enough to send cache_mem_data.  */
#define PBUFSIZ sizeof(cache_mem_data)*2+34

/* Holds the mask of the coreid that has finished executing. Any request 
   after the core has finished executing will not be executed.  */
static int end_status = 0;

/* Simulator or debug agent process id that gets spawned.  */
static int remote_pid = 0;
/* Options passed to spawn the simulator.  */
char **sim_options;
/* Set to 1 if debugging over tcp using a simulator.  */
static int is_simulator = 0;
/* Set to 1 if debugging over tcp using the agent.  */
static int is_agent = 0;
/* Options passed to spawn the agent.  */
char **agent_options;
/* Serial port device, tcp or serial port number.  */
char *serial_port_name;
char *agent_conn;
static char *               octeon_pci_bootcmd = NULL;  /**< Give commands to bootloader running on Octeon in PCI slot. */

/* Version number of the debug stub.  */
static int stub_version;

enum stub_feature { STUB_PERF_EVENT_TYPE };

/* Total number of cores in Octeon. */
#define MAX_CORES 32

/* Number of hw instruction and data breakpoints. */
#define MAX_OCTEON_BREAKPOINTS 4

/* Record hardware instruction breakpoint addresses for each core.
   Max 4 per core. */
static CORE_ADDR hwbp[MAX_CORES][MAX_OCTEON_BREAKPOINTS];

/* Record hardware data breakpoint (watchpoint) addresses.  Max 4 per
   debugging section.  */
static CORE_ADDR hwwp[MAX_CORES][MAX_OCTEON_BREAKPOINTS];
  
/* The address of the hardware watchpoint that caused the debugger to stop.
   Initialized in octeon_wait when the hardware watchpoint is hit and used
   later by octeon_stopped_data_address.  */
CORE_ADDR last_wp_addr;
/* This is non-zero if target stopped for a watchpoint.  */
static int last_wp_p;

/* Some terminal servers need an intial delay before sending the first
   GDB packet.  This avoids the packet being interpreted as a telnet
   negotiation reply.  */
static unsigned transmit_delay;

/* Record performance counters event per core. */
static int perf_status_t[MAX_CORES][2];

#define MAX_NO_PERF_EVENTS (sizeof (perf_events_t) / sizeof (perf_events_t[0]))
                                                                                
/* Enumeration of all supported performance counter types.  */
static struct
{
  const char *event;
  const char *help;
} perf_events_t [] = {
    {"none",            "Turn off the performance counter"},
    {"clk",             "Conditionally clocked cycles"},
    {"issue",           "Instructions issued but not retired"},
    {"ret",             "Instructions retired"},
    {"nissue",          "Cycles no issue"},
    {"sissue",          "Cycles single issue"},
    {"dissue",          "Cycles dual issue"},
    {"ifi",             "Cycle ifetch issued"},
    {"br",              "Branches retired"},
    {"brmis",           "Branch mispredicts"},
    {"j",              "Jumps retired"},
    {"jmis",           "Jumps mispredicted"},
    {"replay",         "Mem Replays"},
    {"iuna",           "Cycles idle due to unaligned_replays"},
    {"trap",           "trap_6a signal"},
    {NULL,             NULL},
    {"uuload",         "Unexpected unaligned loads (REPUN=1)"},
    {"uustore",        "Unexpected unaligned store (REPUN=1)"},
    {"uload",          "Unaligned loads (REPUN=1 or USEUN=1)"},
    {"ustore",         "Unaligned store (REPUN=1 or USEUN=1)"},
    {"ec",             "Exec clocks"},
    {"mc",             "Mul clocks"},
    {"cc",             "Crypto clocks"},
    {"csrc",           "Issue_csr clocks"},
    {"cfetch",         "Icache committed fetches (demand+prefetch)"},
    {"cpref",          "Icache committed prefetches"},
    {"ica",            "Icache aliases"},
    {"ii",             "Icache invalidates"},
    {"ip",             "Icache parity error"},
    {"cimiss",         "Cycles idle due to imiss"},
    {NULL,	       NULL},
    {NULL,	       NULL},
    {"wbuf",           "Number of write buffer entries created"},
    {"wdat",           "Number of write buffer data cycles used"},
    {"wbufld",         "Number of write buffer entries forced out by loads"}, 
    {"wbuffl",         "Number of cycles that there was no available write buffer entry"},
    {"wbuftr",         "Number of stores that found no available write buffer entries"},
    {"badd",           "Number of address bus cycles used"},
    {"baddl2",         "Number of address bus cycles not reflected (i.e. destined for L2)"},
    {"bfill",          "Number of fill bus cycles used"},
    {"ddids",          "Number of Dstream DIDs created"},
    {"idids",          "Number of Istream DIDs created"},
    {"didna",          "Number of cycles that no DIDs were available"},
    {"lds",            "Number of load issues"},
    {"lmlds",          "Number of local memory load"},
    {"iolds",          "Number of I/O load issues"},
    {"dmlds",          "Number of loads that were not prefetches and missed in the cache"},
    {NULL,	       NULL},
    {"sts",            "Number of store issues"},
    {"lmsts",          "Number of local memory store issues"},
    {"iosts",          "Number of I/O store issues"},
    {"iobdma",         "Number of IOBDMAs"},
    {NULL,	       NULL},
    {"dtlb",           "Number of dstream TLB refill, invalid, or modified exceptions"},
    {"dtlbad",         "Number of dstream TLB address errors"},
    {"itlb",           "Number of istream TLB refill, invalid, or address error exceptions"},
    {"sync",           "Number of SYNC stall cycles"},
    {"synciob",        "Number of SYNCIOBDMA stall cycles"},
    {"syncw",          "Number of SYNCWs"}
};

/* Convert number NIB to a hex digit.  */
static int
tohex (int nib)
{
  if (nib < 10)
    return '0' + nib;
  else
    return 'a' + nib - 10;
}

/* Convert hex digit A to a number.  */
static int
from_hex (int a)
{
  if (a == 0)
    return 0;

  if (a >= '0' && a <= '9')
    return a - '0';
  if (a >= 'a' && a <= 'f')
    return a - 'a' + 10;
  if (a >= 'A' && a <= 'F')
    return a - 'A' + 10;
  else if (remote_debug)
    error ("Reply contains invalid hex digit 0x%x", a);
  return 0;
}

static int core_in_mask (unsigned mask, int core)
{
  return !!(mask & (1u<<core));
}

/* Send a GDB packet to the target.  */
static int
puts_octeondebug (char *packet)
{
  if (!octeon_desc)
    error ("Use \"target octeon ...\" first.");

  if (remote_debug)
    printf_unfiltered ("Sending %s\n", packet);

  if (serial_write (octeon_desc, packet, strlen (packet)))
    fprintf_unfiltered (gdb_stderr, "Serial write failed: %s\n",
			safe_strerror (errno));

  return 1;
}

/* Make a GDB packet. The data is always ASCII.
   A debug packet whose contents are <data>
   is encapsulated for transmission in the form:
  
                $ <data> # CSUM1 CSUM2
  
   <data> must be ASCII alphanumeric and cannot include characters
   '$' or '#'.  If <data> starts with two characters followed by
   ':', then the existing stubs interpret this as a sequence number.
  
   CSUM1 and CSUM2 are ascii hex representation of an 8-bit
   checksum of <data>, the most significant nibble is sent first.
   the hex digits 0-9,a-f are used.  */
static void
make_gdb_packet (char *buf, char *data)
{
  int i;
  unsigned char csum = 0;
  int cnt;
  char *p;

  cnt = strlen (data);

  if (cnt > PBUFSIZ)
    error ("make_gdb_packet(): to much data\n");

  /* Start with the packet header */
  p = buf;
  *p++ = '$';

  /* Calculate the checksum */
  for (i = 0; i < cnt; i++)
    {
      csum += data[i];
      *p++ = data[i];
    }

  /* Terminate the data with a '#' */
  *p++ = '#';

  /* add the checksum as two ascii digits */
  *p++ = tohex ((csum >> 4) & 0xf);
  *p++ = tohex (csum & 0xf);
  *p = 0x0;			/* Null terminator on string */
}

/* Make a packet of the stream specified through FMT and other
   varargs and send it to the debug stub. */
static void
make_and_send_packet (char *fmt, ...)
{
  char buf[PBUFSIZ];
  char packet[PBUFSIZ];
  int l;

  va_list args;
  va_start (args, fmt);
  l = vsnprintf (buf, sizeof (buf), fmt, args);
  va_end (args);
  if (l >= sizeof(buf))
    {
      error ("Truncated packet.\n");
      return;
    }
  make_gdb_packet (packet, buf);
  if (puts_octeondebug (packet) == 0)
    error ("Couldn't transmit packet %s\n", packet);
}

/* Read data from target. */
static int
gets_octeondebug (char *packet)
{
  /* State of what we are expecting.  */
  enum
  { S_BEGIN, S_DATA, S_CSUM1, S_CSUM2 } state;
  /* Current input character.  */
  int c;
  /* Running chksum of the S_DATA section.  */
  unsigned char csum;
  /* Pointer to the current addr location in the packet.  */
  char *bp;
  /* True if the packet is invalid and needs to be displayed to the user.  */
  int do_display;

  state = S_BEGIN;
  csum = 0;
  do_display = 0;
  bp = packet;
  packet[0] = 0;

  /* The only way out of this loop is for a valid packet to show up or a
     signal to occur (Control-C twice). Any input received that isn't a valid
     packet will be displayed to the user. This allows the debugger to use the
     same uart as the console. There is a small chance the program will output
     a valid debugger command, but this is unlikely. It has to also get the
     checksum correct. */
  while (1)
    {
      /* Read a character and add it to the packet buffer. A timeout will be
         cause a display since the case statement below doesn't accept it */
      c = readchar (remote_timeout);
      if (c != SERIAL_TIMEOUT)
	*bp++ = c;
      /* Based on the expected character state, determine what we will accept 
       */
      switch (state)
	{
	  /* In the beginning we will only accept a $. All other characters
	     will be displayed to the user */
	case S_BEGIN:
	  if (c == '$')
	    {
	      state = S_DATA;
	      /* Backup bp by one since the $ isn't suppose to be in the
	         final packet */
	      bp--;
	    }
	  else
	    do_display = 1;
	  break;
	  /* Once we've received the $, we expect data for the packet. Right
	     now data can only contain letters and numbers. A # signals the
	     end of the data section */
	case S_DATA:
	  if (c == '#')
	    state = S_CSUM1;
	  else if (c == '$')
	    {
	      /* Backup the pointer so the $ doesn't get displayed */
	      bp--;
	      do_display = 1;
	    }
	  else if ((c >= 32) && (c < 128))
	    csum += c;
	  else
	    do_display = 1;
	  break;
	  /* After we receive a #, we expect two hex digits. This checks for
	     the first */
	case S_CSUM1:
	  if (((c >= 'a') && (c <= 'f')) ||
	      ((c >= 'A') && (c <= 'F')) || ((c >= '0') && (c <= '9')))
	    state = S_CSUM2;
	  else
	    do_display = 1;
	  break;
	  /* We received the first hex digit, now check for the second. If it
	     is there, we have a complete packet */
	case S_CSUM2:
	  if (((c >= 'a') && (c <= 'f')) ||
	      ((c >= 'A') && (c <= 'F')) || ((c >= '0') && (c <= '9')))
	    {
	      unsigned char pktcsum;
	      /* Packet is complete, get the checksum from it */
	      pktcsum = from_hex (*(bp - 2)) << 4;
	      pktcsum |= from_hex (*(bp - 1));
	      /* If the checksum matches what we calculated then accept the
	         packet */
	      if (csum == pktcsum)
		{
		  /* Valid packet, return it to the caller. We strip off the
		     trailer # and two hex digits. The $ was never put on */
		  *(bp - 3) = '\0';
		  if (remote_debug)
		    printf_unfiltered ("Received %s\n", packet);
		  return 1;
		}
	      else
		do_display = 1;
	    }
	  else
	    do_display = 1;
	  break;
	}
      /* If we've exceeded our buffer or any of the above checks failed, the
         packet isn't valid, so display it to the user and start over */
      if (do_display || (bp >= packet + PBUFSIZ))
	{
	  const char *ptr = packet;
	  /* We need to specially handle the $ since it isn't stored in the
	     packet. Only the first state won't print a $ here */
	  if (state != S_BEGIN)
	    putchar_unfiltered ('$');
	  while (ptr < bp)
	    putchar_unfiltered (*ptr++);
	  fflush (stdout);
	  /* As a special case, we don't go back to the begin state if we
	     just received a $ */
	  if (c != '$')
	    state = S_BEGIN;
	  else
	    state = S_DATA;
	  csum = 0;
	  bp = packet;
	  packet[0] = 0;
	  do_display = 0;
	}
    }
}

/* Read a character from the remote system, doing all the fancy remote_timeout
   stuff.  Handles serial errors and EOF.  If TIMEOUT == 0, and no chars,
   returns -1, else returns next char.  Discards chars > 127.  */
static int
readchar (int remote_timeout)
{
  int c, i;

  immediate_quit++;

  for (i = 0; i < 3; i++)
    {
      c = serial_readchar (octeon_desc, remote_timeout);

      if (c >= 0)
	{
	  immediate_quit--;
	  return c & 0x7f;
	}

      if (c == SERIAL_TIMEOUT)
	{
	  if (remote_timeout == 0)
	    return -1;
	  printf_unfiltered ("Ignoring packet error, continuing...\n");
	  continue;
	}
    }

  immediate_quit--;

  if (c == SERIAL_TIMEOUT)
    error ("Timeout reading from remote system.");

  perror_with_name ("readchar");
}

/* The command line interface's stop routine. This function is installed
   as a signal handler for SIGINT. The first time a user requests a
   stop, we call remote_stop to send a break or ^C. If there is no
   response from the target (it didn't stop when the user requested it),
   we ask the user if he'd like to detach from the target. */
static void
octeon_interrupt_connect (int signo)
{
  signal (signo, ofunc);
  octeon_control_c_hit = 1;
  longjmp (octeon_jmp_buf, 1);
}

/* Create octeon_desc.  Spawn the simulator if debugging over tcp.  */

static void
create_connection ()
{
  int j;

  ofunc = (void (*)()) signal (SIGINT, octeon_interrupt_connect);
  octeon_control_c_hit = 0;
  if (setjmp (octeon_jmp_buf))
    {
      close_connection ();
      pop_target ();
      perror_with_name ("Quit");
    }

  if (is_simulator && octeon_spawn_sim)
    simulator_fork (sim_options);

  else if (is_agent)
    agent_fork (agent_options);
    

  for (j = 0; j < 15; j++)
    {
      octeon_desc = serial_open (serial_port_name);
      if (!octeon_desc)
	{
	  sleep (1);
	  continue;
	}
      else
	break;
    }

  if (!octeon_desc
      || (baud_rate != -1
	  && serial_setbaudrate (octeon_desc, baud_rate) != 0))
    {
      if (octeon_desc)
	{
	  serial_close (octeon_desc);
	  octeon_desc = NULL;
	}
      pop_target ();
      perror_with_name (serial_port_name);
    }

  serial_raw (octeon_desc);

  /* Some terminal servers need an intial delay before sending the
     first GDB packet.  This avoids the packet being interpreted as a
     telnet negotiation reply.  */
  if (transmit_delay)
    sleep (transmit_delay);

  inferior_appeared (current_inferior (), ptid_get_pid (inferior_ptid));
  add_thread_silent (inferior_ptid);

  /* Make sure that the cores have stopped.  */
  send_command_get_int_reply_generic ("\003", "T", 0);
  /* Sync up with debug stub on startup. */
  set_step_all (octeon_stepmode);
  set_step_isr (octeon_stepisr);
  get_core_mask ();
  get_focus ();

  stub_version = send_command_get_int_reply_generic ("?", "S", 0);
  if (remote_debug)
    printf_unfiltered ("Stub version: %x\n", stub_version);
  signal (SIGINT, ofunc);

  reinit_frame_cache ();
  registers_changed ();
  stop_pc = regcache_read_pc (get_current_regcache ());
}

/* The simulator kills itself as we close the connection.  This way it
   properly closes the socket so if rerun tries to connect to the same port we
   don't get connected to a stale socket.  We only kill it later as a last
   resort and sleep until things get cleaned up.  */

static void
close_connection ()
{
  if (octeon_desc)
    {
      if (remote_debug)
	fprintf_unfiltered (gdb_stderr, "Closing sim communication\n");
      serial_close (octeon_desc);
      octeon_desc = NULL;
    }

  if (remote_pid && (is_simulator || is_agent))
    {
      int status;
      int ret;
      unsigned i = 0;
      time_t d, t = time (0);
      do {
	i++;
	ret = waitpid (remote_pid, &status, WNOHANG);
	if (ret == -1)
	  perror_with_name ("waitpid");
	d = time (0) - t;
      } while (!((ret == remote_pid
		  && (WIFEXITED (status) || WIFSIGNALED (status)))
		 || d >= 2));
      if (remote_debug)
	fprintf_unfiltered
	  (gdb_stderr,
	   "remote_pid %d (%d) exited with status %d (waited %d-times, %d sec)\n",
	   remote_pid, ret, status, i, (int) d);
      if (d >= 2)
	{
	  if (remote_debug)
	    fprintf_unfiltered (gdb_stderr, "Killing agent or sim\n");
	  kill (remote_pid, SIGKILL);
	  sleep (2);
	}
      remote_pid = 0;
    }
}

/* Fork the simulator by opening a new xterm.
   xterm -e oct-sim options.  */

static void
simulator_fork (char **sim_options)
{
  remote_pid = fork ();

  if (remote_pid < 0)
    perror_with_name ("fork");

  if (remote_pid == 0)
    {
      int i;
      char *errstring;
      sigset_t oldset;
      sigset_t blocked_mask;

      sigaddset (&blocked_mask, SIGINT);
      sigprocmask (SIG_BLOCK, &blocked_mask, &oldset);

      if (remote_debug)
	{
	  int i;

	  printf_unfiltered ("Starting simulator as: ");
	  for (i = 0; sim_options[i]; i++)
	    printf_unfiltered ("%s ", sim_options[i]);
	  printf_unfiltered ("\n");
	}

      /* Pipe all output to /dev/null.  */
      if (!octeon_display_sim)
	{
	  int fd;
	  fd = open ("/dev/null", O_WRONLY);
	  if (fd == -1)
	    perror_with_name ("open /dev/null");
	  close (1);
	  if (dup2 (fd, 1) == -1)
	    perror_with_name ("dup2 stdout");
	  if (dup2 (fd, 2) == -1)
	    perror_with_name ("dup stderr");
	}

      execvp (sim_options[0], sim_options);

      /* If we get here, it's an error. */
      errstring = safe_strerror (errno);
      fprintf (stderr, "Cannot execute \"%s\" because %s", sim_options[0], errstring);
      exit (1);
    }
  /* Sleep 4 seconds for the simulator to start up.  Note the 32bit simulator is slower than
     the 64bit one.  */
  sleep (4);
}

/* Fork the agent.
   oct-debug-agent options.  */

static void
agent_fork (char **agent_options)
{
  remote_pid = fork ();

  if (remote_pid < 0)
    perror_with_name ("fork");

  if (remote_pid == 0)
    {
      int i;
      char *errstring;
      sigset_t oldset;
      sigset_t blocked_mask;

      sigaddset (&blocked_mask, SIGINT);
      sigprocmask (SIG_BLOCK, &blocked_mask, &oldset);

      if (remote_debug)
	{
	  int i;

	  printf_unfiltered ("Starting agent as: ");
	  for (i = 0; agent_options[i]; i++)
	    printf_unfiltered ("%s ", agent_options[i]);
	  printf_unfiltered ("\n");
	}

      /* Pipe all output to /dev/null.  */
      if (!octeon_display_sim)
	{
	  int fd;
	  fd = open ("/dev/null", O_WRONLY);
	  if (fd == -1)
	    perror_with_name ("open /dev/null");
	  close (1);
	  if (dup2 (fd, 1) == -1)
	    perror_with_name ("dup2 stdout");
	  if (dup2 (fd, 2) == -1)
	    perror_with_name ("dup stderr");
	}

      execvp (agent_options[0], agent_options);

      /* If we get here, it's an error. */
      errstring = safe_strerror (errno);
      fprintf (stderr, "Cannot execute \"%s\" because %s", agent_options[0], errstring);
      exit (1);
    }
}

/* Parse the options that needs to be passed to the simulator for spawning.
   The port no is taken from target command. If no options are passed while 
   invoking target option, then default to "-noperf -quiet" options.  */

static int
simulator_setup_options (char **argv)
{
  int argc;
  int sim_argc;
  char *port_no;

  sim_options = (char **) malloc (PBUFSIZ * 2);
  memset (sim_options, '\0', PBUFSIZ * 2);

  sim_argc = 0;

  if (octeon_display_sim)
    {
      /* Invoke the simulator in a new terminal */
      sim_options[sim_argc++] = strdup ("xterm");
      sim_options[sim_argc++] = strdup ("-e");
    }

  /* Copy the name of the executable. */
  sim_options[sim_argc++] = strdup ("oct-sim");

  /* Copy the name of the executable as first parm to oct-sim. */

  if (exec_bfd == 0)
    {
      error ("No executable file specified.\n\
Use the \"file\" or \"exec-file\" command.");
      freeargv (sim_options);
      return 0;
    }
  else
    sim_options[sim_argc++] = strdup (exec_bfd->filename);

  /* By default pass -debug option while invoking oct-sim. */
  sim_options[sim_argc++] = strdup ("-debug");

  for (argc = 1; argv[argc]; argc++, sim_argc++)
    sim_options[sim_argc] = strdup (argv[argc]);

  /* Set the default simulator options if none is passed */
  if (argc < 2)
    {
      sim_options[sim_argc++] = strdup ("-noperf");
      sim_options[sim_argc++] = strdup ("-quiet");
    }

  /* Get the port number from target command */
  port_no = argv[0];

  if (strncmp (port_no, "tcp:", 4) == 0)
    {
      char *tcp_port_no;
      sim_options[sim_argc] = (char *) malloc (sizeof (char *) * 15);
      strcpy (sim_options[sim_argc], "-uart1=");
      tcp_port_no = strchr ((port_no + 4), ':');
      if (tcp_port_no)
	strncat (sim_options[sim_argc++], (tcp_port_no + 1), 7);
      else
	{
	  freeargv (sim_options);
	  error ("No colon in host name!");
	  return -1;
	}
    }
  else
    {
      freeargv (sim_options);
      error
	("Incomplete \"target\" command, use \"help target octeon\" command for correct syntax.");
      return -1;
    }

  return 0;
}

/* Parse the options that needs to be passed to the debugger agent for
   spawning.  */

static int
agent_setup_options (char **argv)
{
  int argc;
  int agent_argc;
  int port;

  agent_options = (char **) malloc (PBUFSIZ * 2);
  memset (agent_options, '\0', PBUFSIZ * 2);

  agent_argc = 0;


  /* Copy the name of the executable. */
  agent_options[agent_argc++] = strdup ("oct-debug-agent");

  /* Copy the name of the executable as first parm to oct-sim. */

  if (exec_bfd == 0)
    {
      error ("No executable file specified.\n\
Use the \"file\" or \"exec-file\" command.");
      freeargv (agent_options);
      return 0;
    }
  else
    agent_options[agent_argc++] = strdup (exec_bfd->filename);

  /* By default pass -q option while invoking oct-debug-agent. */
  agent_options[agent_argc++] = strdup ("-q");

  /* Add the --target option. */
  agent_options[agent_argc++] = strdup("--target");
  agent_options[agent_argc++] = strdup(serial_port_name);
  agent_conn = serial_port_name;

  /* Add the --listen option */
  {
    int sfd;
    struct sockaddr_in sockaddr, peer_addr;
    socklen_t len = sizeof(struct sockaddr_in);
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    listen(sfd, 50);
    getsockname(sfd, (struct sockaddr *) &sockaddr, &len);
    port = ntohs(sockaddr.sin_port);
    close (sfd);
    agent_options[agent_argc++] = strdup("--listen");
    agent_options[agent_argc] = (char *) malloc (sizeof (char *) * 15);
    sprintf (agent_options[agent_argc++], "%d", port);

    serial_port_name = malloc (sizeof("tcp::") + 5);;
    sprintf (serial_port_name, "tcp::%d", port);
  }

  /* Add the --pci-bootcmd option if needed. */
  if (octeon_pci_bootcmd)
    {
      agent_options[agent_argc++] = strdup("--pci-bootcmd");
      agent_options[agent_argc++] = strdup(octeon_pci_bootcmd);
    }
  
  /* Put -- here so that the arguments after this point are taken
     as bootcommand arguments. */
  agent_options[agent_argc++] = strdup("--");

  /* Copy the rest of the arguments. */
  for (argc = 1; argv[argc]; argc++, agent_argc++)
    agent_options[agent_argc] = strdup (argv[argc]);

  return 0;
}
/* Octeon specific commands, available after the target command is invoked.  */
static void
octeon_add_commands ()
{
  /* Dummy variable, initialized when set focus command is invoked but
     ignored by process_core_command. */
  static int dummy_coreid;

  add_setshow_zinteger_cmd ("focus", class_obscure, &dummy_coreid, _("\
Set the core to be debugged."), _("\
Show the focus core of debugger operations."), 
			    NULL, process_core_command, show_core_command, 
			    &setlist, &showlist);

  add_setshow_boolean_cmd ("step-all", no_class, &octeon_stepmode, _("\
Set if \"step\"/\"next\"/\"continue\" commands should be applied to all the cores."), _("\
Show step commands affect all cores."), 
			   NULL, process_stepmode_command, NULL, 
			   &setlist, &showlist);

  add_setshow_boolean_cmd ("step-isr", no_class, &octeon_stepisr, _("\
Set if single-stepping should step in the ISR code."), _("\
Show single-stepping in ISR."),
                           NULL, process_step_isr_command, NULL,
                           &setlist, &showlist);

  add_setshow_string_cmd ("active-cores", no_class, &mask_cores, _("\
Set the cores stopped on execution of a breakpoint by another core."), _(" \
Show the cores stopped on execution of a breakpoint by another core."), 
			  NULL, process_mask_command, NULL, 
			  &setlist, &showlist);

  add_setshow_string_cmd ("perf-event0 <events>", no_class, &perf_event[0], 
			  _(" \
Set event for performance counter0 and the counter is reset to zero.\n"), _(" \
Show the performance counter0 event and counter\n"),
			  NULL, set_performance_counter0_event, 
			  show_performance_counter0_event_and_counter,
			  &setlist, &showlist);
                                                                                
  add_setshow_string_cmd ("perf-event1 <events>", no_class, &perf_event[1], 
			  _(" \
Set event for performance counter1 and the counter is reset to zero\n"), _(" \
Show the performance counter1 event and counter\n"),
                    	  NULL, set_performance_counter1_event, 
			  show_performance_counter1_event_and_counter,
			  &setlist, &showlist);

  mask_cores = xstrdup ("");
}

static int 
check_if_simulator ()
{
  if (serial_port_name)
    {
      if (strncmp (serial_port_name, "tcp:", 4) == 0)
        is_simulator = 1;

      if (strncmp (serial_port_name, "PCI", 3) == 0
	  || strncmp (serial_port_name, "LINUX", 5) == 0
	  || strncmp (serial_port_name, "MACRAIGOR", 5) == 0)
	is_agent = 1;
    }

  return is_simulator;
}

/* Open a connection to a remote debugger. It is called after target command.  */
static void
octeon_open (char *name, int from_tty)
{
  char **argv;
  struct inferior *inf;
  struct symtab *s;

  if (name == NULL)
    error
      ("To open a MIPS remote debugging connection, you need to specify\n"
       "- what serial device is attached to the target board (eg./dev/ttyS0)\n"
       "- the port number of the tcp (eg. :[HOST]:port)\n");

  target_preopen (from_tty);

  push_target (&octeon_ops);
  setup_generic_remote_run (name, pid_to_ptid (100));

  if ((argv = buildargv (name)) == NULL)
    malloc_failure (0);

  make_cleanup_freeargv (argv);

  serial_port_name = xstrdup (argv[0]);

  if (check_if_simulator () && octeon_spawn_sim)
    simulator_setup_options (argv);
  else if (is_agent)
    agent_setup_options (argv);
  else if (strncmp (serial_port_name, "/dev", 4) == 0 && argv[1])
    {
      int baudrate;
      baudrate = atoi (argv[1]);
      if (baudrate == 0)
        printf
	  ("Invalid \"%s\" remote baudrate specified after serial port\n",
	    argv[1]);
      else
        baud_rate = baudrate;
    }

  /* Spawn the simulator while debugging over tcp. Establish the connection
     to octeon_desc by opening a serial port. */
  create_connection ();

  if (from_tty)
    printf ("Remote target %s connected to %s\n", octeon_ops.to_shortname,
	    serial_port_name);


  /* Zero out the stored hardware break points. */
  memset (hwbp, 0, sizeof(hwbp));
  memset (hwwp, 0, sizeof(hwbp));
  /* Set the language of octeon-debug.c to unknown so someone can do
     "set language" without getting a warning.  */
  s = lookup_symtab ("octeon-debug.c");
  if (s)
    s->language = language_unknown;
}

/* Open a connection to a remote debugger for the octeonpci target. It is called after target command.  */
static void
octeon_open_pci (char *name, int from_tty)
{
  char *name1;
  if (name == NULL)
    {
      name1 = strdup ("PCI");
    }
  else
    {
      name1 = malloc (strlen(name) + strlen ("PCI ") + 1);
      strcpy (name1, "PCI ");
      strcat (name1, name);
    }
  octeon_open (name1, from_tty);
  free (name1);
}

/* Close all files and local state before this target loses control. */
static void
octeon_close (int quitting)
{
  end_status = 0;

  if (octeon_desc)
    {
      /* Free the simulator options */
      if (is_simulator)
	freeargv (sim_options);
      if (is_agent)
	freeargv (agent_options);
    }
  /* Kill the simulator and close the serial port. */
  close_connection ();
}


/* The command line interface's stop routine. This function is installed
   as a signal handler for SIGINT. The first time a user requests a
   stop, we call remote_stop to send a break or ^C. If there is no
   response from the target (it didn't stop when the user requested it),
   we ask the user if he'd like to detach from the target. */
static void
octeon_interrupt (int signo)
{
  signal (signo, octeon_interrupt_twice);
  fprintf_unfiltered (gdb_stderr, "Interrupting");
  octeon_stop (inferior_ptid);
  octeon_control_c_hit = 1;
}

/* The user typed ^C twice.  */
static void
octeon_interrupt_twice (int signo)
{
  signal (signo, ofunc);
  target_terminal_ours ();

  if (query ("Interrupted while waiting for the program.\n\
Give up (and stop debugging it)? "))
    {
      octeon_close (0);
      target_mourn_inferior ();
      deprecated_throw_reason (RETURN_QUIT);
    }
  target_terminal_inferior ();

  signal (signo, octeon_interrupt);
}

/* Send COMMAND and expect a reply starting with REPLY.  Return the
   integer value interpreted as hexadecimal value just after REPLY in
   the reply-packet.  On error return ERRORVALUE.  */

static int
send_command_get_int_reply_generic (char *command, char *reply, int errorValue)
{
  char packet[PBUFSIZ];
  size_t reply_len = strlen (reply);

  make_gdb_packet (packet, command);

  if (puts_octeondebug (packet) == 0)
    {
      error ("Couldn't transmit command\n");
      return errorValue;
    }

  while (1)
    {
      if (gets_octeondebug (packet) == 0)
	{
	  error ("Couldn't get reply\n");
	  return errorValue;
	}

      /* Treat packets beginning with "!" as messages to the user from the
         debug monitor */
      if (packet[0] == '!')
	{
	  printf_unfiltered ("%s\n", packet + 1);
	  continue;
	}

      /* If the packet we sent made the target stop we get a status
	 message, ignore it.  */
      if (packet[0] == 'T' && *reply != 'T')
	continue;

      break;
    }

  if (strncmp (&packet[0], reply, reply_len) != 0)
    {
      error ("Received incorrect reply (expected %s got \"%s\")\n", reply, packet);
      return errorValue;
    }
  return strtoul (packet + reply_len, NULL, 16);
}

/* Send a COMMAND to the remote system and get an integer reply. On
   error return ERRORVALUE.  Assumed that response is upper-case
   version of the COMMAND.  */
static int
send_command_get_int_reply (char *command, int error)
{
  char reply[2];

  reply[0] = toupper (command[0]);
  reply[1] = '\0';
  return send_command_get_int_reply_generic (command, reply, error);
}

/* This function is called to make sure the GDB concept of
   focus core matches the lower level debug monitor. It should
   be called anytime it's possible that the two may be out of
   sync.  */
static void
get_focus ()
{
  char prompt[32];
  cache_mem_addr = 0;
  octeon_coreid = send_command_get_int_reply ("f", octeon_coreid);

  sprintf (prompt, "(Core#%d-gdb) ", octeon_coreid);
  if (strcmp ((const char *) prompt, (const char *) get_prompt ()) != 0)
    set_prompt (prompt);

  /* Initialize registers, frame and stack whenever the focus of the core
     is changed.  */
  reinit_frame_cache ();
  registers_changed ();
  stop_pc = regcache_read_pc (get_current_regcache ());
  select_frame (get_current_frame ());
}

static int had_hit_break_once_before = 0;
static int stepping = 0;

static void
octeon_internal_wait (char *packet)
{
  int old_remote_timeout;
  octeon_control_c_hit = 0;

  ofunc = (void (*)()) signal (SIGINT, octeon_interrupt);

  /* The GDB is waiting for a response from debug stub after issuing a
     resume. To wait forever set remote_timeout = -1. */
  old_remote_timeout = remote_timeout;
  remote_timeout = -1;
  while (1)
    {
      if (gets_octeondebug (packet) == 0)
	{
	  if (remote_debug)
	    printf ("Still waiting because %s\n", packet);
	}
      else if (packet[0] == '!')
	{
	  /* Treat packets beginning with "!" as messages to the user from
	     the debug monitor */
	  printf_unfiltered ("%s\n", packet + 1);
	}
      else if ((packet[0] == 'T') || (packet[0] == 'D'))
	return;
    }

  /* Revert to its original value.  */
  remote_timeout = old_remote_timeout;

  signal (SIGINT, ofunc);
}

static int
process_watchpoint_packet (char *packet)
{
 /* The debug stub sends "T8:HWWP_STATUS_BITS" if an hardware watchpoint
    is hit. Hardware data breakpoint status register value is passed 
     in HWWP_STATUS_BITS.  */
  if (packet[0] == 'T' && packet[1] == '8' && packet[2] == ':' && packet[3])
    {
      int i, hwwp_hit;
      /* Read which hardware watchpoint is hit.  */
      hwwp_hit = strtoul (packet+3, NULL, 16) & 0xf;
      /* Find the address of load/store instruction that caused the 
	 watchpoint exception.  */
      for (i = 0; i < MAX_OCTEON_BREAKPOINTS; i++)
	if (core_in_mask(hwwp_hit, i))
	  {
	    last_wp_addr = hwwp[octeon_coreid][i];
	    last_wp_p = 1;
	    break;
	  }
      return 1;
    }
  return 0;
}

static void
process_T_packet (ptid_t ptid, char *packet, struct target_waitstatus *status)
{
  int old_focus = octeon_coreid;
  struct regcache *regcache = get_current_regcache ();
  if (packet[0] != 'T')
    return;
  /* Set the executing to false. */
  set_executing (ptid, 0);
  /* Update the focus of the core to the core that hit the 
     breakpoint/watchpoint.  */
  get_focus ();
  status->kind = TARGET_WAITKIND_STOPPED;
  /* The debug stub sends "T9" for hardware breakpoints and software
     breakpoints.  */
  if (packet[1] == '9')
    status->value.sig = TARGET_SIGNAL_TRAP;
  else
    process_watchpoint_packet (packet);
  /* Update the step-all mode if user has modified.  */
  set_step_all (octeon_stepmode);
  /* Update the ISR stepping mode if user has modified.  */
  set_step_isr (octeon_stepisr);
  /* Get the number of cores that are active.  */
  get_core_mask ();
}

/* Wait until the remote machine stops, then return, storing the status in
   STATUS just as 'wait' would. */
static ptid_t
octeon_wait (struct target_ops *ops, ptid_t ptid,
	     struct target_waitstatus *status, int options)
{
  int sigval = 9;
  char packet[PBUFSIZ];
  
  last_wp_p = 0;

  status->kind = TARGET_WAITKIND_STOPPED;
  status->value.sig = TARGET_SIGNAL_TRAP;

  octeon_internal_wait(packet);

  /* Return the debug execption type */
  if (*packet == 'T')
    process_T_packet (ptid, packet, status);
  /* When break 0x3ff insn is executed then stop the program as this is not a 
     normal breakpoint.  */
  if (*packet == 'D')
    {
      status->kind = TARGET_WAITKIND_EXITED;
      status->value.sig = TARGET_SIGNAL_TRAP;
      status->value.integer = from_hex (packet[1]);
      end_status = (1u << octeon_coreid);
    }
  else if(*packet != 'T')
    {
      error ("Wrong signal from target \n");
      status->kind = TARGET_WAITKIND_STOPPED;
      status->value.sig = TARGET_SIGNAL_ILL;
    }
  if (octeon_control_c_hit)
    {
      status->kind = TARGET_WAITKIND_STOPPED;
      status->value.sig = TARGET_SIGNAL_INT;
    }
  had_hit_break_once_before = 0;
  return inferior_ptid;
}

static int
octeon_supports_non_stop ()
{
  return 0;
}

/* This is the generic stop called via the target vector. When a target
   interrupt is requested, either by the command line or the GUI, we
   will eventually end up here. */
static void
octeon_stop (ptid_t ptid)
{
  /* Send a ^C.  */
  make_and_send_packet ("\003");
}

/* Add a dummy function as 'attach' command expects to be defined if the
   target supports 'to_can_run'. */ 
static void
octeon_attach (struct target_ops *ops, char *args, int from_tty)
{
  error(_("'attach' command not supported in this target"));
}

/* Terminate the open connection to the remote debugger.  Use this
   when you want to detach and do something else with your gdb.  */
static void
octeon_detach (struct target_ops *ops, char *args, int from_tty)
{
  pop_target ();		/* calls octeon_close to do the real work */
  if (from_tty)
    printf_unfiltered ("Ending remote %s debugging\n", target_shortname);
}

/* Tell the remote machine to resume.  */
static void
octeon_resume (struct target_ops *ops, ptid_t ptid, int step, enum target_signal sigal)
{
  cache_mem_addr = 0;
  stepping = !!step;
  if (step)
    make_and_send_packet ("s");
  else
    make_and_send_packet ("c");
  set_resumed_once ();
}

/* Fetch the remote registers. */
static void
octeon_fetch_registers (struct target_ops *ops,
                        struct regcache *regcache, int regno)
{
  struct gdbarch *gdbarch = get_regcache_arch (regcache);
  char reg[MAX_REGISTER_SIZE];
  char *packet = alloca (PBUFSIZ);
  enum bfd_endian byte_order = gdbarch_byte_order (target_gdbarch);

  if (regno > gdbarch_num_regs (gdbarch))
    return;
  make_and_send_packet ("g%04x", regno);

  gets_octeondebug (packet);
  /* We got the number the register holds, but gdb expects to see a value 
     in the target byte ordering.  */
  store_unsigned_integer (reg, register_size (gdbarch, regno), byte_order,
			  strtoull (packet, NULL, 16));
  regcache_raw_supply (regcache, regno, reg);
}

/* Store all registers into remote target */
static void
octeon_store_registers (struct target_ops *ops, struct regcache *regcache, int regno)
{
  ULONGEST val;

  regcache_cooked_read_unsigned (regcache, regno, &val);
  /* This fix is required for "break func" followed by "run" command to work
     if focus is set before. */
  if (regno == MIPS_EMBED_PC_REGNUM)
    {
      CORE_ADDR entry_pt;

      entry_pt = bfd_get_start_address (exec_bfd);

      if (entry_pt == val)
	return;
    }

  make_and_send_packet ("G%04x,%016llx", regno, (unsigned long long) val);
}

/* Get ready to modify the registers array.  On machines which store
   individual registers, this doesn't need to do anything.  On machines
   which store all the registers in one fell swoop, this makes sure
   that registers contains all the registers from the program being
   debugged.  */
static void
octeon_prepare_to_store ()
{
  /* Do nothing, since we can store individual regs */
}

/* Print info on this target.  */
static void
octeon_files_info (struct target_ops *ignore)
{
  if (is_agent)
    printf_unfiltered ("Debugging Octeon on board over %s.\n", agent_conn);
  else if (is_simulator)
    printf_unfiltered ("Debugging Octeon on simulator over a serial line.\n");
  else
    printf_unfiltered ("Debugging Octeon on board over a serial line.\n");
}

/* Write memory data directly to the remote machine.
   This does not inform the data cache; the data cache uses this.
   MEMADDR is the address in the remote memory space.
   MYADDR is the address of the buffer in our space.
   LEN is the number of bytes.
                                                                                
   Returns number of bytes transferred, or 0 (setting errno) for
   error.  */
static unsigned int
octeon_write_inferior_memory (CORE_ADDR memaddr, unsigned char *data,
			      int len)
{
  long i;
  int j;
  char packet[PBUFSIZ];
  char buf[PBUFSIZ];
  char *p;
  int savedlen = len;

  /* Do not send packet to debug_stub when the core finished executing. */

  if (core_in_mask (end_status, octeon_coreid))
    return len;

  cache_mem_addr = 0; /* Invalidate the cache. */
  while (len)
    {

      int newlen = len > sizeof(cache_mem_data) ? sizeof(cache_mem_data) : len;
      p = buf + snprintf (buf, sizeof (buf), "M%016llx,%04x:",
		          (unsigned long long) memaddr, newlen);
      for (j = 0; j < newlen; j++)
	{				/* copy the data in after converting it */
	  *p++ = tohex ((data[j] >> 4) & 0xf);
	  *p++ = tohex (data[j] & 0xf);
	}
      *p = 0;
      make_and_send_packet (buf);

      do
	{
	  if (gets_octeondebug (packet) == 0)
	    error ("couldn't receive packet \n");
	  else if (packet[0] == '!')
	    printf_filtered ("%s\n", packet + 1);
        }
      while (packet[0] == '!');

      if (*packet == '-')
        return savedlen - len;
      memaddr += newlen;
      data += newlen;
      len -= newlen;
    }

  return savedlen;
}

/* Helper function to octeon_read_inferior_memory(). If the memory
   address requested to read is already in cache_mem_addr return it
   instead of getting it from debug_stub.  Read sizeof(cache_mem_data)
   at a time and do always aligned loads.  */
static int
cache_mem_read (CORE_ADDR memaddr, char *myaddr, int len)
{
  if (len > sizeof (cache_mem_data))
    len = sizeof (cache_mem_data);

  if ((cache_mem_addr) && (memaddr >= cache_mem_addr)
      && (memaddr < cache_mem_addr + sizeof (cache_mem_data)))
    {
      if (memaddr + len > cache_mem_addr + sizeof (cache_mem_data))
	len = cache_mem_addr + sizeof (cache_mem_data) - memaddr;

      memcpy (myaddr, cache_mem_data + (memaddr - cache_mem_addr), len);
      return len;
    }
  else
    {
      char packet[sizeof (cache_mem_data) * 2 + 4];
      int j;
      char *ptr = cache_mem_data;
      char *hexptr = packet;
      /* Align the size. */
      CORE_ADDR memaddr_align = memaddr & -(CORE_ADDR)sizeof(cache_mem_data);
      make_and_send_packet ("m%016llx,%04x", (unsigned long long) memaddr_align,
			    (int) sizeof (cache_mem_data));

      do
	{
	  if (gets_octeondebug (packet) == 0)
	    error ("couldn't receive packet \n");
	  else if (packet[0] == '!')
	    printf_filtered ("%s\n", packet + 1);
	}
      while (packet[0] == '!');

      if (*packet == 0 || *packet == '-')
	return 0;

      for (j = 0; j < sizeof (cache_mem_data); j++)
	{
	  *ptr++ = from_hex (*hexptr) * 16 + from_hex (*(hexptr + 1));
	  hexptr += 2;
	}
      cache_mem_addr = memaddr_align;

      if (memaddr + len > cache_mem_addr + sizeof (cache_mem_data))
	len = cache_mem_addr + sizeof (cache_mem_data) - memaddr;

      memcpy (myaddr, cache_mem_data + (memaddr - cache_mem_addr), len);
      return len;
    }
}

/* Read memory data directly from the remote machine.
   This does not use the data cache; the data cache uses this.
   MEMADDR is the address in the remote memory space.
   MYADDR is the address of the buffer in our space.
   LEN is the number of bytes.

   Returns number of bytes transferred, or 0 for error.  */
static int
octeon_read_inferior_memory (CORE_ADDR memaddr, char *myaddr, int len)
{
  int amount_left = len;
  while (amount_left)
    {
      int count = cache_mem_read (memaddr, myaddr, amount_left);
      /* cache_mem_read returns 0 in case of error. */
      if (count == 0)
	return count;
      memaddr += count;
      myaddr += count;
      amount_left -= count;
    }
  return len;
}

/* Read and write memory of and from target respectively. */
static int
octeon_xfer_inferior_memory (CORE_ADDR memaddr, gdb_byte * myaddr, int len,
			     int write, struct mem_attrib *attrib,
			     struct target_ops *target)
{
  if (write)
    return octeon_write_inferior_memory (memaddr, myaddr, len);
  else
    return octeon_read_inferior_memory (memaddr, myaddr, len);
}

static void
octeon_kill ()
{
  target_mourn_inferior ();
}

/* At present the simulator is loading the program into memory and executing it
   so no need to do anything. */
static void
octeon_load (char *args, int from_tty)
{
  /* No need to call generic_load.  While debugging over serial port or over
     tcp, the program is loaded into memory by the bootloader.  */
  return;
}

/* Clean up when a program exits.  */

static void
octeon_mourn_inferior ()
{
  close_connection ();
  unpush_target (&octeon_ops);
  generic_mourn_inferior ();	/* Do all the proper things now */
}

static int
octeon_multicore_hw_breakpoint ()
{
  return 1;
}

static int
octeon_multicore_hw_watchpoint ()
{
  return 1;
}

/* Return 1 if hardware watchpoint is hit, otherwise return 0.  */
static int
octeon_stopped_by_watchpoint (void)
{
  return last_wp_p;
}

/* Update the address of the hardware watchpoint that hit.  */

static int
octeon_stopped_data_address (struct target_ops *target, CORE_ADDR *addrp)
{
  if (octeon_stopped_by_watchpoint ())
    {
      *addrp = last_wp_addr;
      return 1;
    }
  return 0;
}

/* CNT is the number of hardware breakpoint to be installed. Return non-zero
   value if the value does not cross the max limit (4 for Octeon).  */

static int
octeon_can_use_watchpoint (int type, int cnt, int othertype)
{
  int i; 

  if (cnt > MAX_OCTEON_BREAKPOINTS)
    {
      printf_unfiltered ("Octeon supports only four hardware breakpoints/watchpoints\n");
      return -1;
    }
  return 1; 
}

static int 
octeon_get_core_number ()
{
  if (remote_debug)
    fprintf_unfiltered (gdb_stderr, "get_core_number: %d\n", octeon_coreid);
  return octeon_coreid;
}

static void
octeon_set_core_number (int core)
{
  if (remote_debug)
    fprintf_unfiltered (gdb_stderr, "set_core_number: %d\n", core);
  set_focus (core);
  get_focus ();
}

/* Octeon has 4 instruction hardware breakpoints per core. Insert hardware
   breakpoints that are applied to each core by changing the focus. */

static int
octeon_insert_mc_hw_breakpoint (struct gdbarch *gdbarch, struct bp_target_info *bp_tgt, int core)
{
  int i;
  int saved_core = octeon_coreid;
  
  if (!core_in_mask (octeon_activecores, core))
    return -1;

  for (i = 0; i < MAX_OCTEON_BREAKPOINTS; i++)
    {
      if (hwbp[core][i] == 0)
        {
	  /* Change the focus of the core to insert hardware breakpoint.
	     Insert only if focus can be changed.  */
	  if (set_focus (core))
	    return -1;
	    
	  hwbp[core][i] = bp_tgt->placed_address;
	  make_and_send_packet("Zi%x,%016llx", i, bp_tgt->placed_address);
	  set_focus (saved_core);
	  return 0;
	}
     }
  return -1;
}

/* Remove hardware breakpoints. */
static int
octeon_remove_mc_hw_breakpoint (struct gdbarch *gdbarch, struct bp_target_info *bp_tgt, int core)
{
  int i;
  int saved_core = octeon_coreid;

  /* Do not send packet to debug_stub when the core finished executing. */
  if (core_in_mask (end_status, octeon_coreid))
    return -1;
  
  if (!core_in_mask (octeon_activecores, core))
    return -1;

  for (i = 0; i < MAX_OCTEON_BREAKPOINTS; i++)
    {
      if (hwbp[core][i] == bp_tgt->placed_address)
        {
	  /* Change the focus of the core to remove hardware breakpoint.
	     Remove only if focus can be changed.  */
	  if (set_focus (core))
	    return -1;
	    
	  hwbp[core][i] = 0;
	  make_and_send_packet("zi%x", i);
	  set_focus (saved_core);
	  return 0;
	}
     }
  return -1;
}

static int
octeon_insert_hw_breakpoint (struct gdbarch *gdbarch, struct bp_target_info *bp_tgt)
{
  gdb_assert (0);
}

static int
octeon_remove_hw_breakpoint (struct gdbarch *gdbarch, struct bp_target_info *bp_tgt)
{
  gdb_assert (0);
}


/* Octeon has 4 data hardware breakpoints (watchpoints) per core. At present
   watchpoints are implemented implemented globally instead of per core.
   Total there are only 4 hardware watchpoints, any request after that will
   be treated as software watchpoints.  */

static int
octeon_insert_mc_watchpoint (CORE_ADDR addr, int len, int type, struct expression *cond, int core)
{
  int i;
  int saved_core = octeon_coreid;

  /* Do not send packet to debug_stub when the core finished executing. */
  if (core_in_mask (end_status, octeon_coreid))
    return -1;
  
  if (!core_in_mask (octeon_activecores, core))
    return -1;

  for (i = 0; i < MAX_OCTEON_BREAKPOINTS; i++)
    {
      if (hwwp[core][i] == 0)
        {
	  int stubtype;

	  /* Change the focus of the core to insert hardware watchpoint.
	     Remove only if focus can be changed.  */
	  if (set_focus (core))
	    return -1;

	  hwwp[core][i] = addr;
	  /* Make sure watchpoint type in debugger and debug stub mean
	     the same.  */
	  stubtype = (type == hw_write) ? 2 : ((type == hw_read) ? 1 : 3); 
          make_and_send_packet ("Zd%x,%016llx,%x,%x", i, 
				(unsigned long long)addr, len, stubtype);
	  set_focus (saved_core);
          return 0;
        }
    }
  return -1;
}

/* Remove hardware watchpoints. */

static int
octeon_remove_mc_watchpoint (CORE_ADDR addr, int len, int type, struct expression *cond, int core)
{
  int i;
  int saved_core = octeon_coreid;

  /* Do not send packet to debug_stub when the core finished
     executing. */
  if (core_in_mask (end_status, octeon_coreid))
    return 0;
                                                                                
  for (i = 0; i < MAX_OCTEON_BREAKPOINTS; i++)
    {
      if (hwwp[core][i] == addr)
        {
	  /* Change the focus of the core to remove hardware watchpoint.
	     Remove only if focus can be changed.  */
	  if (set_focus (core))
	    return -1;

          hwwp[core][i] = 0;
          make_and_send_packet ("zd%x", i);

	  set_focus (saved_core);
          return 0;
        }
    }
  return -1;
}

static int
octeon_insert_watchpoint (CORE_ADDR addr, int len, int type, struct expression *cond)
{
  gdb_assert (0);
}

static int
octeon_remove_watchpoint (CORE_ADDR addr, int len, int type, struct expression *cond)
{
  gdb_assert (0);
}

/* Insert a breakpoint on targets that don't have any better breakpoint
   support.  We read the contents of the target location and stash it,
   then overwrite it with a breakpoint instruction.  ADDR is the target
   location in the target machine.  CONTENTS_CACHE is a pointer to
   memory allocated for saving the target contents.  It is guaranteed
   by the caller to be long enough to save sizeof BREAKPOINT bytes (this
   is accomplished via BREAKPOINT_MAX).  */

static int
octeon_insert_breakpoint (struct gdbarch *gdbarch, struct bp_target_info *bp_tgt)
{
  return memory_insert_breakpoint (gdbarch, bp_tgt);
}

static int
octeon_remove_breakpoint (struct gdbarch *gdbarch, struct bp_target_info *bp_tgt)
{
  return memory_remove_breakpoint (gdbarch, bp_tgt);
}

static void
convert_active_cores_to_string ()
{
  char output[MAX_CORES * 3 + 1];
  int i;
  int loc;

  /* Convert the bitmask into a comma seperated core list */
  loc = 0;
  for (i = 0; i < MAX_CORES; i++)
    {
      if (core_in_mask (octeon_activecores, i))
	loc += sprintf (output + loc, "%d,", i);
    }

  /* Remove the ending comma */
  if (loc)
    output[loc - 1] = 0;

  /* Only update GDB's variable if the value changed */
  if ((mask_cores == NULL) || (strcmp (mask_cores, output) != 0))
    {
      if (mask_cores)
	xfree (mask_cores);
      mask_cores = savestring (output, strlen (output));
    }
}

/* Update the focus of the core. Do not update the prompt. This is required
   to send hardware breakpoints to the core that is not in focus. When the
   cores resume the hardware breakpoints that are inserted to the other
   cores will also get executed. Return 0 on success and 1 on failure.  */
static int
set_focus (int coreid)
{
  char buf[64];
  int orig_coreid = octeon_coreid;

  /* No need to change the focus of the core if it is the focused core. */
  if (octeon_coreid == coreid)
    return 0;

  snprintf (buf, sizeof (buf), "F%x", coreid);
  octeon_coreid = send_command_get_int_reply (buf, -1);
  return (octeon_coreid != -1 && octeon_coreid == orig_coreid);
}

/* Get the number of the core to be debugged. */

static void
process_core_command (char *args, int from_tty,
			     struct cmd_list_element *c)
{
  cache_mem_addr = 0;
  /* Get coreid from cmd_list_element struct. */
  set_focus (*(int *) c->var);

  get_focus ();
  /* Print the frame of the current stack.  */
  print_stack_frame (get_selected_frame (NULL), 1, SRC_AND_LOC);
}

static void
show_core_command (struct ui_file *file, int from_tty, 
                   struct cmd_list_element *c, const char *value)
{
  printf_filtered ("The currently debugged core is %d\n", octeon_coreid);
}

/* If stepmode is set to 1, make all cores step/next. By default the step/next
   command gets applied to only the focused core. */
static void
process_stepmode_command (char *args, int from_tty,
			 struct cmd_list_element *c)
{
  cache_mem_addr = 0;
  set_step_all (octeon_stepmode);
}

/* Set octeon_stepmode (step-all) in debug stub. This is never modified by
   debug stub. Sync debug stub as per changes made by the user.  */
static int
set_step_all (int stepmode)
{
  char buf[3];

  buf[0] = 'A';
  buf[1] = octeon_stepmode ? '1' : '0';
  buf[2] = '\0';
  octeon_stepmode = send_command_get_int_reply (buf, stepmode);

  return octeon_stepmode;
}

/* If ISR stepping is set to 1, all cores step into the ISR.
 * By default the soft stepping mode is off. */
static void
process_step_isr_command (char *args, int from_tty,
                                 struct cmd_list_element *c)
{
  cache_mem_addr = 0;
  set_step_isr (octeon_stepisr);
}

/* Set octeon_stepisr in debug stub. This is never modified by
   debug stub. Sync debug stub as per changes made by the user.  */
static int
set_step_isr (int step_isr)
{
  char buf[3];

  buf[0] = 'J';
  buf[1] = octeon_stepisr ? '1' : '0';
  buf[2] = '\0';
  octeon_stepisr = send_command_get_int_reply (buf, step_isr);

  return octeon_stepisr;
}

#define skip_whitespace(ptr)		\
  do {					\
    while (*ptr && isspace(*ptr))	\
      ptr ++;				\
  } while (0)

/*  Parse the CORES list and return the mask. */
static unsigned
parse_core_list (char *cores)
{
  char quoted = 0;
  unsigned mask = 0;
  char *end;
  int coreid;

  /* The string was empty, assume all cores want to be in the list. */
  if (cores == NULL || cores[0] == 0)
    return mask;

  /* Skip over ' and ". */
  if (*cores == '\"' || *cores == '\'')
    {
      quoted = *cores;
      cores++;
    }

  while (1)
    {
      skip_whitespace (cores);

      /* Check for the end of list. */
      if (quoted)
	{
	  if (cores[0] == 0)
	    error ("No quote at the end of the list.");

	  /* End of quoted command, everything is okay.  */
	  if (cores[0] == quoted && cores[1] == 0)
	    return mask;

	  if (cores[0] == quoted)
	    error ("Quote not ending the list.");
	}
      else if (cores[0] == 0)
	return mask;

      coreid = strtol (cores, &end, 10);

      mask |= (1u<<coreid);

      /* There was no numbers to parse. */
      if (cores == end)
	error ("The list should only contain numbers.");

      cores = end;

      skip_whitespace (cores);

      /* If we don't have a comma, we must either have a syntax error
         or at the end of the list.  */
      if (cores[0] != ',')
	break;
      cores++;
    }
  /* Check for the end of list. */
  if (quoted)
    {
      if (cores[0] == 0)
	error ("No quote at the end of the list.");

      /* End of quoted command, everything is okay. */
      if (cores[0] == quoted && cores[1] == 0)
	return mask;

      if (cores[0] == quoted)
	error ("Quote not ending the list.");
    }
  else if (cores[0] == 0)
    return mask;
  error ("The list should only contain numbers.");
}

/* Set the number of cores to stop on debug exception. */
static void
process_mask_command (char *args, int from_tty,
			     struct cmd_list_element *c)
{
  char buf[64];

  volatile struct gdb_exception e;
  TRY_CATCH (e, RETURN_MASK_ERROR)
    {
      octeon_activecores = parse_core_list (mask_cores);
      snprintf (buf, sizeof (buf), "I%04x", octeon_activecores);
      octeon_activecores = send_command_get_int_reply (buf, octeon_activecores);
    }

  convert_active_cores_to_string ();
  /* Was there an exception */
  if (e.reason < 0)
    {
      /* Rethrow the exception as we cleaned up from it via
	 convert_active_cores_to_string. */
      throw_exception (e);
    }
}

/* Get the octeon_activecores from debug stub.  */
static void 
get_core_mask ()
{
   octeon_activecores = send_command_get_int_reply ("i", octeon_activecores);
   convert_active_cores_to_string ();
}

/* Return true if the FEATURE is supported in a particular stub_version.  */
static int
check_stub_feature (enum stub_feature feature)
{
  if (feature == STUB_PERF_EVENT_TYPE)
    return stub_version >= 10;
  
  gdb_assert (1);
  return 0;
}

/* Set performance counter counters based on event.
   COUNTER - 1 = performance counter 1, 0 = performance counter 0 */

static void
set_performance_counter_event (int counter)
{
  int i;
  int pevent = -1;
                                                                                
  if (perf_event[counter])
    {
      for (i = 0; i < MAX_NO_PERF_EVENTS; i++)
        {
          if (perf_events_t[i].event 
	      && strcmp (perf_event[counter], perf_events_t[i].event) == 0)
	    {
              pevent = i;
	      perf_status_t[octeon_coreid][counter] = i;
	      make_and_send_packet ("e%d%x", counter + 1, i);
	      break;
	    }
        }
    }

  if (pevent == -1)
    {
      printf_unfiltered 
	("These are the performance counter events supported by Octeon:\n\n");
      printf_unfiltered ("Event            Description\n\n");
      for (i = 0; i < MAX_NO_PERF_EVENTS; i++)
	if (perf_events_t[i].event)
          printf_unfiltered ("%-16s %s\n", perf_events_t[i].event, perf_events_t[i].help);
    }
}
                                                                                
static void
set_performance_counter0_event (char *args, int from_tty, struct cmd_list_element *c)
{
  set_performance_counter_event (0);
}
                                                                                
static void
set_performance_counter1_event (char *args, int from_tty, struct cmd_list_element *c)
{
  set_performance_counter_event (1);
}

/* Show performance counter counters for the events set.
   COUNTER - 1 = performance counter 1, 0 = performance counter 0 */

static void
show_performance_counter_event_and_counter (int counter)
{
  char *packet = alloca (PBUFSIZ);
  unsigned long perf_counter, event;
  
  if (perf_event[counter])
    {
      if (counter)
        make_and_send_packet ("e4");
      else
        make_and_send_packet ("e3");

      gets_octeondebug(packet);

      perf_counter = strtoul (packet, &packet, 16);
      packet++;
      if (check_stub_feature (STUB_PERF_EVENT_TYPE))
        /* The debug stub returns "counter,event_type" packet.  */
	event = strtoul (packet, NULL, 16);
      else
	/* The debug stub returns only counter, get the event_type from
	   perf_status_t stored in set_performance_counter_event.  */ 
	event = perf_status_t[octeon_coreid][counter];


      if (event >= MAX_NO_PERF_EVENTS
	  || perf_events_t[event].event == NULL)
        printf_unfiltered ("Performance counter%d for none event is %ld\n",
			    counter, perf_counter);
      else
        printf_unfiltered ("Performance counter%d for \"%s\" event is %ld\n",
			   counter, perf_events_t[event].event, perf_counter);
    }
  else
    printf_unfiltered ("Performance counter%d event is not set.\n", counter); 
}

static void
show_performance_counter0_event_and_counter (struct ui_file *file, int from_tty, 
				  	     struct cmd_list_element *c, 
					     const char *value)
{
  show_performance_counter_event_and_counter (0);
}

static void
show_performance_counter1_event_and_counter (struct ui_file *file, int from_tty, 
					     struct cmd_list_element *c, 
					     const char *value)
{
  show_performance_counter_event_and_counter (1);
}

/* Forward it to remote-run.  */

static int 
octeon_can_run (void)
{
  return generic_remote_can_run_target (octeon_ops.to_shortname);
}

/* octeonpci will never be able to run as we already changed the target
   to octeon.  */

static int 
octeon_can_run_pci (void)
{
  return 0;
}

static void
init_octeon_ops (void)
{
  /* Since we boot in the target command we need to be able to set
     pci-bootcmd before that so this has to be global.  */
  add_setshow_string_cmd ("pci-bootcmd", no_class, &octeon_pci_bootcmd, _("\
Set boot command (shell command) needed for PCI boot as debugger resets the \n\
board internally on a \"run\" command. Default is oct-pci-reset\n"), _("\
Show boot command for PCI boot\n"),
			  NULL, NULL, NULL,
			  &setlist, &showlist);

  add_setshow_boolean_cmd ("spawn-sim", no_class, &octeon_spawn_sim, _("\
Set to zero to not spawn the simulator upon the target command."), _("\
Show whether the simulator would be spawned upon the target command."),
			  NULL, NULL, NULL, &setlist, &showlist);

  add_setshow_boolean_cmd ("display-sim", no_class, &octeon_display_sim, _("\
Set to zero to hide the spawned simulator rather display in its window"), _("\
Show whether the simulator is displayed in its own window (otherwise hidden)"),
			  NULL, NULL, NULL, &setlist, &showlist);


  add_setshow_zinteger_cmd ("transmit-delay", no_class, &transmit_delay, _("\
Set delay (sec) before trasmitting first packet"), _("\
Show delay (sec) before trasmitting first packet"),
			    NULL, NULL, NULL, &setlist, &showlist);

  octeon_add_commands ();

  octeon_ops.to_shortname = "octeon";
  octeon_ops.to_longname = "Remote Octeon target";
  octeon_ops.to_doc = "Use a remote Octeon via serial line or a tcp port.\n"
    "Arguments are the name of the device for the serial line,\n"
    "the speed to connect at in bits per second or the\n"
    "tcp port for tcp connection. eg\n"
    "target octeon /dev/ttyS0\n" "target octeon tcp:[HOST]:65258";
  octeon_ops.to_open = octeon_open;
  octeon_ops.to_close = octeon_close;
  octeon_ops.to_attach = octeon_attach;
  octeon_ops.to_detach = octeon_detach;
  octeon_ops.to_resume = octeon_resume;
  octeon_ops.to_wait = octeon_wait;
  octeon_ops.to_fetch_registers = octeon_fetch_registers;
  octeon_ops.to_store_registers = octeon_store_registers;
  octeon_ops.to_prepare_to_store = octeon_prepare_to_store;
  octeon_ops.deprecated_xfer_memory = octeon_xfer_inferior_memory;
  octeon_ops.to_files_info = octeon_files_info;
  octeon_ops.to_insert_breakpoint = octeon_insert_breakpoint;
  octeon_ops.to_remove_breakpoint = octeon_remove_breakpoint;

  octeon_ops.to_can_use_hw_breakpoint = octeon_can_use_watchpoint;
  octeon_ops.to_insert_mc_hw_breakpoint = octeon_insert_mc_hw_breakpoint;
  octeon_ops.to_remove_mc_hw_breakpoint = octeon_remove_mc_hw_breakpoint;
  octeon_ops.to_insert_hw_breakpoint = octeon_insert_hw_breakpoint;
  octeon_ops.to_remove_hw_breakpoint = octeon_remove_hw_breakpoint;
  octeon_ops.to_multicore_hw_breakpoint = octeon_multicore_hw_breakpoint;
  octeon_ops.to_get_core_number = octeon_get_core_number;
  octeon_ops.to_set_core_number = octeon_set_core_number;

  octeon_ops.to_multicore_hw_watchpoint = octeon_multicore_hw_watchpoint;
  octeon_ops.to_insert_mc_watchpoint = octeon_insert_mc_watchpoint;
  octeon_ops.to_remove_mc_watchpoint = octeon_remove_mc_watchpoint;
  octeon_ops.to_remove_watchpoint = octeon_remove_watchpoint;
  octeon_ops.to_insert_watchpoint = octeon_insert_watchpoint;
  octeon_ops.to_stopped_data_address = octeon_stopped_data_address;
  octeon_ops.to_stopped_by_watchpoint = octeon_stopped_by_watchpoint;

  octeon_ops.to_kill = octeon_kill;
  octeon_ops.to_load = octeon_load;
  octeon_ops.to_can_run = octeon_can_run;
  octeon_ops.to_mourn_inferior = octeon_mourn_inferior;
  octeon_ops.to_stop = octeon_stop;
  octeon_ops.to_stratum = process_stratum;
  octeon_ops.to_has_all_memory = default_child_has_all_memory;
  octeon_ops.to_has_memory = default_child_has_memory;
  octeon_ops.to_has_stack = default_child_has_stack;
  octeon_ops.to_has_registers = default_child_has_registers;
  octeon_ops.to_has_execution = default_child_has_execution;
  octeon_ops.to_magic = OPS_MAGIC;
  octeon_ops.to_create_inferior = generic_remote_create_inferior;
  octeon_ops.to_supports_non_stop = octeon_supports_non_stop;

  octeon_pci_ops = octeon_ops;
  octeon_pci_ops.to_shortname = "octeonpci";
  octeon_pci_ops.to_longname = "Remote connection to Octeon over PCI";
  octeon_pci_ops.to_doc = "Connect to Octeon through PCI. No parameters are necessary.\n"
                      "Example: target octeonpci";
  octeon_pci_ops.to_open = octeon_open_pci;
  octeon_pci_ops.to_can_run = octeon_can_run_pci;
};

void
_initialize_octeon (void)
{
  struct cmd_list_element *c;
  init_octeon_ops ();
  add_target (&octeon_ops);
  add_target (&octeon_pci_ops);
}
