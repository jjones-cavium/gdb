/* Provide run command from remote targets.

   Copyright (C) 2006-2008 Cavium Networks.

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

/* When run is invoked on remote targets issue the equivalent of the
   last target command and a continue (implicit via run_command_1).
   In a target;run sequence, run should not reopen the target but
   simply issue a continue.  Even if the target closes we should be
   able to find the last target used (if it was registered with us)
   and invoke it with the same target arguments.  */

#include "defs.h"
#include "target.h"
#include "gdb_assert.h"
#include "inferior.h"
#include <string.h>
#include "cli/cli-cmds.h"
#include "cli/cli-decode.h"
#include "gdbthread.h"

/* Original to_remote handler.  */
static void (*remote_resume) (struct target_ops *ops, ptid_t, int, enum target_signal);

/* Count the number of resumes since the last open.  If we just hit
   the debug exception handler after the target command there is no
   need to reopen the target.  */
static int resumed_once;

/* Remember the open function of the last target opened.  This
   setup_generic_remote_run does need to pass its target_ops.  (Note
   that current_target is not equivalent of the target_ops of the
   current target but it is a union of all the pused targets.) */
static void (*last_target_to_open) (char *, int);
/* Arguments to the last target command.  */
static char *last_args;
/* Save this for debugging purposes.  */
static char * last_to_shortname;

/* We replace run with our own run and call continue and run from there.  This
   is the original run function.  */
cmd_cfunc_ftype *orig_run_func;
/* This is the continue command.  */
struct cmd_list_element *continue_cmd_list_element;


/* Don't reopen target if all we did so far was to connect to the
   target.  */

static int
reopen_p ()
{
  if (remote_debug)
    fprintf_unfiltered (gdb_stdlog, "  resumed_once: %d\n", resumed_once);
  return resumed_once;
}

/* Handle run by issuing a target command.  Try to do this by printing
   as little as possible.  The subsequent continue will be issued by our
   caller.  */

void
generic_remote_create_inferior (struct target_ops *target, char *execfile, char *args, char **env,
				int from_tty)
{
  if (remote_debug)
    fprintf_unfiltered (gdb_stdlog, "generic_remote_create_inferior:\n");

  if (!reopen_p ())
    {
      if (remote_debug)
	fprintf_unfiltered (gdb_stdlog, "  no need to reopen target\n");

      /* Reset stop_soon to print breakpoint information after
	 disabling it in start_remote().  */
      init_wait_for_inferior ();
      
      return;
    }

  if (remote_debug)
    fprintf_unfiltered (gdb_stdlog, "  reopening target %s with %s\n",
			last_to_shortname, last_args);

  /* We are already killed at this point so don't prompt the user
     again in target_preopen() if the target is still alive.  */
  if (last_to_shortname
      && strcmp (current_target.to_shortname, last_to_shortname) == 0)
    pop_target ();

  /* Don't print the frame where we stop after connecting only the one
     after continue.  */
  never_print_frame = 1;

  /* No need to reset resumed_once here as this will call back to us as
     setup_generic_remote_run below.  */
  last_target_to_open (last_args, 0);
  never_print_frame = 0;

  /* Reset stop_soon to print breakpoint information after disabling
     it in start_remote().  */
  init_wait_for_inferior ();
}

/* Capture resume call to know whether we have started effectively
   debugging the program.  */

static void
generic_remote_resume (struct target_ops *ops, ptid_t ptid, int step, enum target_signal signal)
{
  if (remote_debug && !resumed_once)
    fprintf_unfiltered (gdb_stdlog, "generic_remote_resume: resumed once\n");

  resumed_once = 1;
  remote_resume (ops, ptid, step, signal);
}

/* This can be called from the targets's to_can_run handler.  If we've
   seen it how to run a target we can run it again.  */

int
generic_remote_can_run_target (char *shortname)
{
  return last_to_shortname && strcmp (shortname, last_to_shortname) == 0;
}

/* Install our own run command.  When run is issued after the target has just
   connected we want to emulate a continue instead of a regular run which
   would kill the target and reestablish the connection.  There are a few
   other approaches we have tried in the past to achive the same effect:

   1. Only set inferior_ptid after the first resume (run/continue) command:

      The problem with this is that between the target command and the resume
      the kill command would report an error and fail.  The reason is that
      inferior_ptid is unset so the program is assumed to have not started
      yet.

   2. In addition to 1 override the kill command to avoid the error message
   and complete the kill.

      The problem here is more subtle.  The regcache machinery gets confused
      by the pids and eventually a stale regcache is used (with the sentinel
      frame) which leads to a crash.  It seems that once the target can query
      the state of the inferior, inferior_ptid is expecte to be something
      valid.

   Overriding run avoids the delayed initialization of inferior_ptid which
   should be more robust.  */

static void
remote_run_run_command (char *arg, int from_tty)
{
  if (current_target.to_resume == generic_remote_resume
      && !resumed_once)
    {
      if (remote_debug)
	fprintf_unfiltered
	  (gdb_stdlog,
	   "remote_run_run_command: executing continue instead of run\n");
      cmd_func (continue_cmd_list_element, arg, from_tty);
    }
  else
    {
      if (remote_debug)
	fprintf_unfiltered
	  (gdb_stdlog,
	   "remote_run_run_command: executing original run\n");
      orig_run_func (arg, from_tty);
    }
}

/* Call this from the target open function.  Also set
   to_create_inferior to generic_remote_create_inferior and call
   generic_remote_can_run_target from the to_can_run handler.  */

void
setup_generic_remote_run (char *args, ptid_t ptid)
{
  if (remote_debug)
    fprintf_unfiltered (gdb_stdlog, "Setting up generic_remote target\n");

  remote_resume = current_target.to_resume;
  current_target.to_resume = generic_remote_resume;

  last_target_to_open = current_target.to_open;
  last_args = args ? xstrdup (args) : NULL;
  last_to_shortname = current_target.to_shortname;

  inferior_ptid = ptid;

  resumed_once = 0;

  if (!orig_run_func)
    {
      char run_str[] = "run";
      char continue_str[] = "continue";
      char *p;
      struct cmd_list_element *c;

      p = run_str;
      c = lookup_cmd (&p, cmdlist, "", 0, 1);
      gdb_assert (c);
      gdb_assert (c->type == not_set_cmd);
      /* Save the function, the cmd_list_element is freed with the new run
	 command.  */
      orig_run_func = c->function.cfunc;

      add_com ("run", c->class, remote_run_run_command, c->doc);
      add_com_alias ("r", "run", class_run, 1);

      p = continue_str;
      continue_cmd_list_element = lookup_cmd (&p, cmdlist, "", 0, 1);
      gdb_assert (continue_cmd_list_element);
    }
}
