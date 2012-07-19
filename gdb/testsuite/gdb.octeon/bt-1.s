	.text
	.align	2
	.align	3
	.globl	main
	.ent	main
main:
	.frame	$sp,8,$31		# vars= 0, regs= 1/0, args= 0, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	daddiu	$sp,$sp,-8
	sd	$31,0($sp)
	jal	foo
	nop

	li	$2,1			# 0x1
	ld	$31,0($sp)
	j	$31
	daddiu	$sp,$sp,8

	.set	macro
	.set	reorder
	.end	main
	.size	main, .-main
	.align	2
	.align	3
	.ent	foo
foo:
	.frame	$sp,8,$31		# vars= 0, regs= 1/0, args= 0, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	jal	bar
	nop

1:
	b	1b
	nop

	.set	macro
	.set	reorder
	.end	foo
	.size	foo, .-foo
	
	.align	2
	.align	3
	.ent	bar
bar:
	.frame	$sp,8,$31		# vars= 0, regs= 1/0, args= 0, gp= 0
	.mask	0x80000000,-8
	.fmask	0x00000000,0
	.set	noreorder
	.set	nomacro
	
	j	$31
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

	.set	macro
	.set	reorder
	.end	bar
	.size	bar, .-bar

	.ident	"GCC: (GNU) 4.1.2 (Cavium Networks Version: 1_7_0, build 37)"
