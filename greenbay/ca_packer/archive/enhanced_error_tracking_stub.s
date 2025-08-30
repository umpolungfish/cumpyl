	.file	"enhanced_error_tracking_stub.c"
	.text
	.globl	write_to_stderr
	.type	write_to_stderr, @function
write_to_stderr:
	endbr64
	movq	%rdi, %rsi
	xorl	%edx, %edx
.L2:
	cmpb	$0, (%rsi,%rdx)
	je	.L5
	incq	%rdx
	jmp	.L2
.L5:
	movl	$1, %eax
	movl	$2, %edi
#APP
# 27 "enhanced_error_tracking_stub.c" 1
	syscall
# 0 "" 2
#NO_APP
	ret
	.size	write_to_stderr, .-write_to_stderr
	.globl	exit_with_code
	.type	exit_with_code, @function
exit_with_code:
	endbr64
	movl	$60, %eax
#APP
# 41 "enhanced_error_tracking_stub.c" 1
	syscall
# 0 "" 2
#NO_APP
.L7:
	jmp	.L7
	.size	exit_with_code, .-exit_with_code
	.section	.rodata.str1.1,"aMS",@progbits,1
.LC0:
	.string	"CA-Packer Enhanced Error Tracking Stub Executing\n"
	.text
	.globl	_start
	.type	_start, @function
_start:
	endbr64
	leaq	.LC0(%rip), %rdi
	call	write_to_stderr
	movl	$60, %eax
	movl	$42, %edi
#APP
# 41 "enhanced_error_tracking_stub.c" 1
	syscall
# 0 "" 2
#NO_APP
.L9:
	jmp	.L9
	.size	_start, .-_start
	.ident	"GCC: (Ubuntu 11.4.0-1ubuntu1~22.04.2) 11.4.0"
	.section	.note.GNU-stack,"",@progbits
	.section	.note.gnu.property,"a"
	.align 8
	.long	1f - 0f
	.long	4f - 1f
	.long	5
0:
	.string	"GNU"
1:
	.align 8
	.long	0xc0000002
	.long	3f - 2f
2:
	.long	0x3
3:
	.align 8
4:
