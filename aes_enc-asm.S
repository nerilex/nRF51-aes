/* aes_enc-asm.S */
/*
    This file is part of the AVR-Crypto-Lib.
    Copyright (C) 2006-2015 Daniel Otte (daniel.otte@rub.de)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/


	.syntax unified
	.cpu cortex-m0
	.thumb

.global qxtimes
qxtimes:
	ldr r2, =0x80808080
	ands r2, r2, r0
	ldr r1, =0xfefefefe
	lsls r0, r0, #1
	ands r0, r0, r1
	lsrs r2, r2, #3
	eors r0, r0, r2
	lsrs r2, r2, #1
	eors r0, r0, r2
	lsrs r2, r2, #2
	eors r0, r0, r2
	lsrs r2, r2, #1
	eors r0, r0, r2
	bx lr
