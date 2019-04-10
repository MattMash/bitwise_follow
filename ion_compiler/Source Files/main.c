//
//  main.c
//  ion_compiler
//
//  Created by Matthew Mashiane on 2019/04/07.
//  Copyright © 2019 Matthew Mashiane. All rights reserved.
//
#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>

#include "common.c"
#include "lex.c"
#include "ast.c"

int main(int argc, const char * argv[]) {
    buf_test();
    lex_test();
    str_intern_test();
    ast_tests();
    return 0;
}
