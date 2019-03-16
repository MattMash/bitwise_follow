#include <stdio.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <assert.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <stdarg.h>
#define MAX(x, y) ((x) >= (y) ? (x) : (y))

// strechy buffers

typedef struct BufHdr {
    size_t len;
    size_t cap;
    char buf[0];
} BufHdr;

void *xrealloc(void *ptr, size_t num_bytes) {
    ptr = realloc(ptr, num_bytes);
    if (!ptr) {
        perror("xrealloc failed");
        exit(1);
    }
    return ptr;
}

void *xmalloc(size_t num_bytes) {
     void *ptr = malloc(num_bytes);
    if (!ptr) {
        perror("xmalloc failed");
        exit(1);
    }
    return ptr;
}


void fatal(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("FATAL: ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
    exit(1);
}

#define buf__hdr(b) ((BufHdr *)((char *)b - offsetof(BufHdr,buf)))
#define buf__fits(b, n) (buf_len(b) + (n) <= buf_cap(b))
#define buf__fit(b, n) (buf__fits(b, n) ? 0 : ((b) = buf__grow((b), buf_len(b) + (n), sizeof(*(b)))))

#define buf_len(b) ((b) ? buf__hdr(b)->len : 0)
#define buf_cap(b) ((b) ? buf__hdr(b)->cap : 0)
#define buf_push(b, x) (buf__fit(b, 1), b[buf_len(b)] = (x), buf__hdr(b)->len++)
#define buf_free(b) ((b) ? (free(buf__hdr(b)), (b) = NULL) : 0)

void *buf__grow(const void *buf, size_t new_len, size_t elem_size) {
    size_t new_cap = MAX(1 + 2*buf_cap(buf), new_len);
    assert(new_len <= new_cap);
    size_t new_size = new_cap * elem_size + sizeof(BufHdr);
    BufHdr *new_hdr;
    if (buf) {
        new_hdr = xrealloc(buf__hdr(buf), new_size);
    } else {
        new_hdr = xmalloc(new_size);
        new_hdr->len = 0;
    }
    new_hdr->cap = new_cap;
    return new_hdr->buf;
}

void buf_test() {
    int *buf = NULL;
    buf_push(buf, 42);
    buf_push(buf, 1234);

    for (int i = 0; i < buf_len(buf); i++) {
//        printf("%d\n", buf[i]);
    }
    buf_free(buf);
}

typedef struct InternStr {
    size_t len;
    const char *str;
} InternStr;

static InternStr *interns;

const char *str_intern_range(const char *start, const char *end) {
    size_t len = end - start;
    for ( size_t i = 0; i < buf_len(interns); i++) {
        if (interns[i].len == len && strncmp(interns[i].str, start, len) == 0) {
            return interns[i].str;
        }
    }
    char *str = xmalloc(len + 1);
    str[len] = 0;
    memcpy(str, start, len);
    buf_push(interns, ((InternStr){len, str}));
    return str;
}

const char *str_intern(const char *str) {
    return str_intern_range(str, str + strlen(str));
}

void str_intern_test() {
    char x[] = "hello";
    char y[] = "hello";
    assert(x!=y);
    const char *px = str_intern(x);
    const char *py = str_intern(y);
    assert( px == py);
    char z[] = "hello!";
    const char *pz = str_intern(z);
    assert(pz != px);
}

// lexing: translating char stream to token stream
// e.g 1234 (x+y) translates to '1234' '(' 'x' '+' 'y' ')'

typedef enum TokenKind {
    TOKEN_INT = 128,
    TOKEN_NAME
} TokenKind;

typedef struct Token {
    TokenKind kind;
    const char *start;
    const char *end;
    union {
        int val;
        const char *name;
        // ...
    };
} Token;

// Warning: this returns a pointer to a static internal buffer, so it will be overwritten next call.
const char *token_kind_name(TokenKind kind) {
    static char buf[256];
    switch (kind) {
        case TOKEN_INT:
            sprintf(buf, "integer");
            break;
        case TOKEN_NAME:
            sprintf(buf, "name");
            break;
        default:
            if (kind < 128 && isprint(kind)) {
                sprintf(buf, "%c", kind);
            } else {
                sprintf(buf, "<ASCII %d>", kind);
            }
            break;
    }
    return buf;
}

Token token;
const char *stream;

const char *keyword_if;
const char *keyword_for;
const char *keyword_while;

void init_keywords() {
    keyword_if = str_intern("if");
    keyword_for = str_intern("for");
    keyword_while = str_intern("while");
}

void next_token() {
    token.start = stream;
    switch(*stream) {
        case '0':
        case '1':
        case '2':
        case '3':
        case '4':
        case '5':
        case '6':
        case '7':
        case '8':
        case '9': {
            int val = 0;
            while(isdigit(*stream)) {
                val *= 10;
                val += *stream++ - '0';
            }
            token.kind = TOKEN_INT;
            token.val = val;
            break;
        }
        case 'a':
        case 'b':
        case 'c':
        case 'd':
        case 'e':
        case 'f':
        case 'g':
        case 'h':
        case 'i':
        case 'j':
        case 'k':
        case 'l':
        case 'm':
        case 'n':
        case 'o':
        case 'p':
        case 'q':
        case 'r':
        case 's':
        case 't':
        case 'u':
        case 'v':
        case 'w':
        case 'x':
        case 'y':
        case 'z':
        case 'A':
        case 'B':
        case 'C':
        case 'D':
        case 'E':
        case 'F':
        case 'G':
        case 'H':
        case 'I':
        case 'J':
        case 'K':
        case 'L':
        case 'M':
        case 'N':
        case 'O':
        case 'P':
        case 'Q':
        case 'R':
        case 'S':
        case 'T':
        case 'U':
        case 'V':
        case 'W':
        case 'X':
        case 'Y':
        case 'Z':
        case '_':
            while(isalnum(*stream) || *stream == '_') {
                stream++;
            }
            token.kind = TOKEN_NAME;
            token.name = str_intern_range(token.start, stream);
            break;
        default:
            token.kind = *stream++;
            break;
            
        }
        token.end = stream;
}

void init_stream(const char *str) {
    stream = str;
    next_token();
}

void print_token(Token token) {
        switch (token.kind) {
            case TOKEN_INT:
                printf("TOKEN INT: %d\n", token.val);
                break;
            case TOKEN_NAME:
                printf("TOKEN NAME: %.*s\n", (int)(token.end - token.start),token.start);
                break;
            default:
                printf("TOKEN: %c\n", token.kind);
                break;
    }
}

inline static bool is_token(TokenKind kind) {
    return token.kind == kind;
}

inline static bool is_token_name(const char *name) {
    return token.kind == TOKEN_NAME && token.name == name;
}

inline static bool match_token(TokenKind kind) {
    if (is_token(kind)) {
        next_token();
        return true;
    } else {
        return false;
    }
}

inline static bool expect_token(TokenKind kind) {
    if (is_token(kind)) {
        next_token();
        return true;
    } else {
        fatal("expected token: %s, received: %s", token_kind_name(kind), token_kind_name(token.kind));
        return false;
    }
}

void lex_test() {
    char *source = "XY+(XY)098_Hello_World123456+89878";
    stream = source;
    next_token();
    while (token.kind) {
//        print_token(token);
        next_token();
    }
}

/*
 expr3 = INT | '(' expr ')'
 expr2 = [-]expr3
 expr1 = expr2 ([/ *] expr2)*
 expr0 = expr1 ([+-] expr1)*
 expr = expr0
 */
int parse_expr(void);

int parse_expr3() {
    int val;
    if (is_token(TOKEN_INT)) {
        val = token.val;
        next_token();
    } else if (match_token('(')){
        val = parse_expr();
        expect_token(')');
    } else {
        fatal("expected interger or (, got %s", token_kind_name(token.kind));
        return 0;
    }

    return val;
}

int parse_expr2() {
    if (match_token('-')) {
        return -parse_expr3();
    } else {
        return parse_expr3();
    }
}

int parse_expr1() {
    int val = parse_expr2();
    while (is_token('*') || is_token('/')) {
        char op = token.kind;
        next_token();
        int rval = parse_expr2();
        if (op == '*') {
            val *= rval;
        } else {
            assert(op == '/');
            assert(rval != 0);
            val /= rval;
        }
    }
    return val;
}

int parse_expr0() {
    int val = parse_expr1();
    while (is_token('+') || is_token('-')) {
        char op = token.kind;
        next_token();
        int rval = parse_expr1();
        if (op == '+') {
            val += rval;
        } else {
            assert(op == '-');
            val -= rval;
        }
    }
    return val;
}

int parse_expr() {
    return parse_expr0();
}

int test_parse_expr(const char *expr) {
    init_stream(expr);
    return parse_expr();
}

void parse_test() {
    assert(test_parse_expr("1") == 1);
    assert(test_parse_expr("(1)") == 1);
    assert(test_parse_expr("-1") == -1);
    assert(test_parse_expr("1-2-3") == -4);
    assert(test_parse_expr("2*3+4*5") == 26);
    assert(test_parse_expr("2+-5") == -3);
    assert(test_parse_expr("2*(3+4)*5") == 70);
}

int main(int argc, const char * argv[]) {
    buf_test();
    lex_test();
    str_intern_test();
    parse_test();
    return 0;
}
