/* Target-dependent code for GNU/Linux on MIPS processors.

   Copyright 2006-2012 Free Software Foundation, Inc.

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
