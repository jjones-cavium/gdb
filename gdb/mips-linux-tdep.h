/* Target-dependent code for GNU/Linux on MIPS processors.

   Copyright (C) 2006-2013 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

void mips_supply_gregset (struct regcache *, const mips_elf_gregset_t *);
void mips_fill_gregset (const struct regcache *, mips_elf_gregset_t *, int);
void mips_supply_fpregset (struct regcache *, const mips_elf_fpregset_t *);
void mips_fill_fpregset (const struct regcache *, mips_elf_fpregset_t *, int);

void mips64_supply_gregset (struct regcache *, const mips64_elf_gregset_t *);
void mips64_fill_gregset (const struct regcache *,
			  mips64_elf_gregset_t *, int);
void mips64_supply_fpregset (struct regcache *,
			     const mips64_elf_fpregset_t *);
void mips64_fill_fpregset (const struct regcache *,
			   mips64_elf_fpregset_t *, int);

/* Return 1 if MIPS_RESTART_REGNUM is usable.  */

int mips_linux_restart_reg_p (struct gdbarch *gdbarch);

/* MIPS Signals -- adapted from linux/arch/mips/include/asm/signal.h.  */

enum mips_signals 
  {
    MIPS_SIGHUP    =  1,	/* Hangup (POSIX).  */
    MIPS_SIGINT    =  2,	/* Interrupt (ANSI).  */
    MIPS_SIGQUIT   =  3,	/* Quit (POSIX).  */
    MIPS_SIGILL    =  4,	/* Illegal instruction (ANSI).  */
    MIPS_SIGTRAP   =  5,	/* Trace trap (POSIX).  */
    MIPS_SIGIOT    =  6,	/* IOT trap (4.2 BSD).  */
    MIPS_SIGABRT   =  MIPS_SIGIOT, /* Abort (ANSI).  */
    MIPS_SIGEMT    =  7,
    MIPS_SIGFPE    =  8,	/* Floating-point exception (ANSI).  */
    MIPS_SIGKILL   =  9,	/* Kill, unblockable (POSIX).  */
    MIPS_SIGBUS    = 10,	/* BUS error (4.2 BSD).  */
    MIPS_SIGSEGV   = 11,	/* Segmentation violation (ANSI).  */
    MIPS_SIGSYS    = 12,
    MIPS_SIGPIPE   = 13,	/* Broken pipe (POSIX).  */
    MIPS_SIGALRM   = 14,	/* Alarm clock (POSIX).  */
    MIPS_SIGTERM   = 15,	/* Termination (ANSI).  */
    MIPS_SIGUSR1   = 16,	/* User-defined signal 1 (POSIX).  */
    MIPS_SIGUSR2   = 17,	/* User-defined signal 2 (POSIX).  */
    MIPS_SIGCHLD   = 18,	/* Child status has changed (POSIX).  */
    MIPS_SIGCLD    = MIPS_SIGCHLD, /* Same as SIGCHLD (System V).  */
    MIPS_SIGPWR    = 19,	/* Power failure restart (System V).  */
    MIPS_SIGWINCH  = 20,	/* Window size change (4.3 BSD, Sun).  */
    MIPS_SIGURG    = 21,	/* Urgent condition on socket (4.2 BSD).  */
    MIPS_SIGIO     = 22,	/* I/O now possible (4.2 BSD).  */
    MIPS_SIGPOLL   = MIPS_SIGIO, /* Pollable event occurred (System V).  */
    MIPS_SIGSTOP   = 23,	/* Stop, unblockable (POSIX).  */
    MIPS_SIGTSTP   = 24,	/* Keyboard stop (POSIX).  */
    MIPS_SIGCONT   = 25,	/* Continue (POSIX).  */
    MIPS_SIGTTIN   = 26,	/* Background read from tty (POSIX).  */
    MIPS_SIGTTOU   = 27,	/* Background write to tty (POSIX).  */
    MIPS_SIGVTALRM = 28,	/* Virtual alarm clock (4.2 BSD).  */
    MIPS_SIGPROF   = 29,	/* Profiling alarm clock (4.2 BSD).  */
    MIPS_SIGXCPU   = 30,	/* CPU limit exceeded (4.2 BSD).  */
    MIPS_SIGXFSZ   = 31,	/* File size limit exceeded (4.2 BSD).  */
    MIPS_SIGRTMIN  = 32,	/* Minimum RT signal.  */
    MIPS_SIGRTMAX  = 128 - 1	/* Maximum RT signal.  */
  };
