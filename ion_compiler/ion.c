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

#define MAX(x, y) ((x) >= (y) ? (x) : (y))

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

void syntax_error(const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    printf("Syntax Error: ");
    vprintf(fmt, args);
    printf("\n");
    va_end(args);
}

/////////////////////////////// Strechy Buffer //////////////////////////////////////////////

typedef struct BufHdr {
    size_t len;
    size_t cap;
    char buf[];
} BufHdr;

#define buf__hdr(b) ((BufHdr *)((char *)b - offsetof(BufHdr,buf)))
#define buf__fits(b, n) (buf_len(b) + (n) <= buf_cap(b))
#define buf__fit(b, n) (buf__fits(b, n) ? 0 : ((b) = buf__grow((b), buf_len(b) + (n), sizeof(*(b)))))

#define buf_len(b) ((b) ? buf__hdr(b)->len : 0)
#define buf_cap(b) ((b) ? buf__hdr(b)->cap : 0)
#define buf_push(b, ...) (buf__fit(b, 1),  (b)[buf__hdr(b)->len++] = (__VA_ARGS__))
#define buf_end(b) ((b) + buf_len(b))
#define buf_free(b) ((b) ? (free(buf__hdr(b)), (b) = NULL) : 0)

void *buf__grow(const void *buf, size_t new_len, size_t elem_size) {
    assert(buf_cap(buf) <= (SIZE_MAX - 1)/2);
    size_t new_cap = MAX(1 + 2*buf_cap(buf), new_len);
    assert(new_len <= new_cap);
    assert(new_cap <= (SIZE_MAX - offsetof(BufHdr, buf))/elem_size);
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
    assert(buf_len(buf) == 0);
    int n = 1024;
    for (int i = 0; i < n; i++) {
        buf_push(buf, i);
    }
    assert(buf_len(buf) == n);
    for (int i = 0; i < buf_len(buf); i++) {
        assert(buf[i] == i);
    }
    buf_free(buf);
    assert(buf == NULL);
    assert(buf_len(buf) == 0);
}
/////////////////////////////// String Intern ///////////////////////////////////////////////
typedef struct InternStr {
    size_t len;
    const char *str;
} Intern;

static Intern *interns;

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
    buf_push(interns, (Intern){len, str});
    return str;
}

const char *str_intern(const char *str) {
    return str_intern_range(str, str + strlen(str));
}

void str_intern_test() {
    char a[] = "hello";
    assert(strcmp(a, str_intern(a)) == 0);
    assert(str_intern(a) == str_intern(a));
    assert(str_intern(str_intern(a)) == str_intern(a));
    char b[] = "hello";
    assert(a != b);
    assert(str_intern(a) == str_intern(b));
    char c[] = "hello!";
    assert(str_intern(a) != str_intern(c));
    char d[] = "hell";
    assert(str_intern(a) != str_intern(d));
}

//////////////////////////////////// Lexing /////////////////////////////////////////////////

// lexing: translating char stream to token stream
// e.g 1234 (x+y) translates to '1234' '(' 'x' '+' 'y' ')'

typedef enum TokenKind {
    // Reserve first 128 values for one-char tokens
    TOKEN_EOF = 0,
    TOKEN_LAST_CHAR = 127,
    TOKEN_INT,
    TOKEN_FLOAT,
    TOKEN_STR,
    TOKEN_NAME,
    TOKEN_INC,
    TOKEN_DEC,
    TOKEN_LSHIFT,
    TOKEN_RSHIFT,
    TOKEN_EQ,
    TOKEN_NOTEQ,
    TOKEN_LTEQ,
    TOKEN_GTEQ,
    TOKEN_AND,
    TOKEN_OR,
    TOKEN_ADD_ASSIGN,
    TOKEN_SUB_ASSIGN,
    TOKEN_COLON_ASSIGN,
    TOKEN_OR_ASSIGN,
    TOKEN_AND_ASSIGN,
    TOKEN_XOR_ASSIGN,
    TOKEN_LSHIFT_ASSIGN,
    TOKEN_RSHIFT_ASSIGN,
    TOKEN_MUL_ASSIGN,
    TOKEN_DIV_ASSIGN,
    TOKEN_MOD_ASSIGN
} TokenKind;

typedef enum TokenMod {
    TOKENMOD_NONE,
    TOKENMOD_HEX,
    TOKENMOD_BIN,
    TOKENMOD_OCT,
    TOKENMOD_CHAR
} TokenMod;

typedef struct Token {
    TokenKind kind;
    TokenMod mod;
    const char *start;
    const char *end;
    union {
        uint64_t int_val;
        const char *str_val;
        const char *name;
        double float_val;
        // ...
    };
} Token;

size_t copy_token_kind_str(char *dest, size_t dest_size, TokenKind kind) {
    size_t n = 0;
    switch (kind) {
        case TOKEN_EOF:
            n = snprintf(dest, dest_size, "end of file");
            break;
        case TOKEN_INT:
            n = snprintf(dest, dest_size, "integer");
            break;
        case TOKEN_FLOAT:
            n = snprintf(dest, dest_size, "float");
            break;
        case TOKEN_NAME:
            n = snprintf(dest, dest_size, "name");
            break;
        default:
            if (kind < 128 && isprint(kind)) {
                n = snprintf(dest, dest_size, "%c", kind);
            } else {
                n = snprintf(dest, dest_size, "<ASCII %d>", kind);
            }
            break;
    }
    return n;
}

// Warning: this returns a pointer to a static internal buffer, so it will be overwritten next call.
const char *token_kind_str(TokenKind kind) {
    static char buf[256];
    size_t n = copy_token_kind_str(buf, sizeof(buf), kind);
    assert(n + 1 <= sizeof(buf));
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

uint8_t char_to_digit[256] = {
    ['0'] = 0,
    ['1'] = 1,
    ['2'] = 2,
    ['3'] = 3,
    ['4'] = 4,
    ['5'] = 5,
    ['6'] = 6,
    ['7'] = 7,
    ['8'] = 8,
    ['9'] = 9,
    ['a'] = 10,
    ['b'] = 11,
    ['c'] = 12,
    ['d'] = 13,
    ['e'] = 14,
    ['f'] = 15,
    ['A'] = 10,
    ['B'] = 11,
    ['C'] = 12,
    ['D'] = 13,
    ['E'] = 14,
    ['F'] = 15,
};

double scan_float() {
    const char *start = stream;
    while (isdigit(*stream)) {
        stream++;
    }
    if (*stream == '.') {
        stream++;
    }
    while (isdigit(*stream)) {
        stream++;
    }
    if (tolower(*stream) == 'e') {
        stream++;
        if (*stream == '+' || *stream == '-') {
            stream++;
        }
        if (!isdigit(*stream)) {
            syntax_error("Expected digit after float literal exponent, found '%c'.", *stream);
        }
        while (isdigit(*stream)) {
            stream++;
        }
    }
    const char *end = stream;
    double val = strtod(start, NULL);
    if (val == HUGE_VAL || val == -HUGE_VAL) {
        syntax_error("Float literal overflow");
    }
    token.float_val = val;
    token.kind = TOKEN_FLOAT;
    return val;
}

uint64_t scan_int() {
    uint64_t base = 10;
    if (*stream == '0') {
        stream++;
        if (tolower(*stream) == 'x') {
            stream++;
            base = 16;
            token.mod = TOKENMOD_HEX;
        } else if (*stream == 'b') {
            stream++;
            base = 2;
            token.mod = TOKENMOD_BIN;
        }  else if (isdigit(*stream)) {
            base = 8;
            token.mod = TOKENMOD_OCT;
        } else {
            token.kind = TOKEN_INT;
            token.int_val = 0;
            base = 10;
            return 0;
        }
    }
    
    uint64_t val = 0;
    for(;;) {
        uint64_t digit = char_to_digit[*stream];
        if (digit == 0 && *stream != '0') {
            break;
        }
        if (digit >= base) {
            syntax_error("Digit '%c' out of range for base %llu", *stream, base);
        }
        if (val > (UINT64_MAX - digit)/base) {
            syntax_error("Integer literal overflow");
            while (isdigit(*stream)) {
                stream++;
            }
            val = 0;
        }
        val = val*base + digit;
        stream++;
    }
    token.int_val = val;
    token.kind = TOKEN_INT;
    return val;
}

char escape_to_char[256] = {
    ['n'] = '\n',
    ['r'] = '\r',
    ['t'] = '\t',
    ['v'] = '\v',
    ['b'] = '\b',
    ['a'] = '\a',
    ['0'] = 0
};

void scan_char() {
    assert(*stream == '\'');
    stream++;
    
    char val = 0;
    if (*stream == '\'') {
        syntax_error("Char literal cannot be empty");
    } else if (*stream == '\n') {
        syntax_error("Char literal cannot contain newline");
    } else if (*stream == '\\') {
        stream++;
        val = escape_to_char[*stream];
        if (val == 0 && *stream != 0) {
            syntax_error("Invalid char literal escape '\\%c'", *stream);
        }
        stream++;
    } else {
        val = *stream;
        stream++;
    }
    if (*stream != '\'') {
        syntax_error("Expected closing char quote, got '%c'", *stream);
    } else {
        stream++;
    }
    
    token.kind = TOKEN_INT;
    token.int_val = val;
    token.mod = TOKENMOD_CHAR;
}

void scan_str() {
    assert(*stream == '"');
    stream++;
    char *str = NULL;
    while (*stream && *stream != '"') {
        char val = *stream;
        if (val == '\n') {
            syntax_error("String literal cannot contain newline");
        } else if (val == '\\') {
            stream++;
            val = escape_to_char[*stream];
            if (val == 0 && *stream != 0) {
                syntax_error("Invalid string literal escape '\\%c'", *stream);
            }
        }
        buf_push(str, val);
        stream++;
    }
    
    if (*stream) {
        assert(*stream == '"');
        stream++;
    } else {
        syntax_error("Unexpected end of file within string qutoes");
    }
    buf_push(str, 0);
    token.kind = TOKEN_STR;
    token.str_val = str;
}

#define CASE1(c, c1, k1) \
case c: \
token.kind = *stream++; \
if (*stream == c1) { \
token.kind = k1; \
stream++;\
}\
break;

#define CASE2(c, c1, k1, c2, k2) \
case c: \
token.kind = *stream++; \
if (*stream == c1) { \
token.kind = k1; \
stream++;\
} else if (*stream == c2) { \
token.kind = k2; \
stream++; \
} \
break;

void next_token() {
top:
    token.start = stream;
    token.mod = 0;
    switch(*stream) {
        case ' ': case '\n': case '\t': case '\r':  case '\v':
            while (isspace(*stream)) {
                stream++;
                goto top;
            }
            break;
        case '\'':
            scan_char();
            break;
        case '"':
            scan_str();
            break;
        case '.':
            scan_float();
            break;
        case '0': case '1': case '2': case '3': case '4': case '5': case '6': case '7': case '8': case '9': {
            while (isdigit(*stream)) {
                stream++;
            }
            char c = *stream;
            stream = token.start;
            if (c == '.' || tolower(c) == 'e') {
                scan_float();
            } else {
                scan_int();
            }
            break;
        }
        case 'a': case 'b': case 'c': case 'd': case 'e': case 'f': case 'g': case 'h': case 'i': case 'j':
        case 'k': case 'l': case 'm': case 'n': case 'o': case 'p': case 'q': case 'r': case 's': case 't':
        case 'u': case 'v': case 'w': case 'x': case 'y': case 'z':
        case 'A': case 'B': case 'C': case 'D': case 'E': case 'F': case 'G': case 'H': case 'I': case 'J':
        case 'K': case 'L': case 'M': case 'N': case 'O': case 'P': case 'Q': case 'R': case 'S': case 'T':
        case 'U': case 'V': case 'W': case 'X': case 'Y': case 'Z':
        case '_':
            while(isalnum(*stream) || *stream == '_') {
                stream++;
            }
            token.kind = TOKEN_NAME;
            token.name = str_intern_range(token.start, stream);
            break;
        case '<':
            token.kind = *stream++;
            if (*stream == '<') {
                token.kind = TOKEN_LSHIFT;
                stream++;\
                if (*stream == '=') {
                    token.kind = TOKEN_LSHIFT_ASSIGN;
                    stream++;
                }
            } else if (*stream == '=') {
                token.kind = TOKEN_LTEQ;
                stream++;
            }
            break;
        case '>':
            token.kind = *stream++;
            if (*stream == '>') {
                token.kind = TOKEN_RSHIFT;
                stream++;
                if (*stream == '=') {
                    token.kind = TOKEN_RSHIFT_ASSIGN;
                    stream++;
                }
            } else if (*stream == '=') {
                token.kind = TOKEN_GTEQ;
                stream++;
            }
            break;
        CASE1('^', '=', TOKEN_XOR_ASSIGN)
        CASE1(':', '=', TOKEN_COLON_ASSIGN)
        CASE1('/', '=', TOKEN_DIV_ASSIGN)
        CASE1('*', '=', TOKEN_MUL_ASSIGN)
        CASE1('%', '=', TOKEN_MOD_ASSIGN)
        CASE2('+', '+', TOKEN_INC, '=', TOKEN_ADD_ASSIGN)
        CASE2('-', '-', TOKEN_DEC, '=', TOKEN_SUB_ASSIGN)
        CASE2('&', '=', TOKEN_AND_ASSIGN, '&', TOKEN_AND)
        CASE2('|', '=', TOKEN_OR_ASSIGN, '|', TOKEN_OR)
        
        default:
            token.kind = *stream++;
            break;
        }
        token.end = stream;
}

#undef CASE1
#undef CASE2

void init_stream(const char *str) {
    stream = str;
    next_token();
}

void print_token(Token token) {
        switch (token.kind) {
            case TOKEN_INT:
                printf("TOKEN INT: %llu\n", token.int_val);
                break;
            case TOKEN_FLOAT:
                printf("TOKEN FLOAT: %f\n", token.float_val);
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
        char buf[256];
        copy_token_kind_str(buf, sizeof(buf), kind);
        fatal("expected token %s, got %s", buf, token_kind_str(token.kind));
        return false;
    }
}

#define assert_token(x) assert(match_token(x))
#define assert_token_name(x) assert(token.name == str_intern(x) && match_token(TOKEN_NAME))
#define assert_token_int(x) assert(token.int_val == (x) && match_token(TOKEN_INT))
#define assert_token_float(x) assert(token.float_val == (x) && match_token(TOKEN_FLOAT))
#define assert_token_str(x) assert(strcmp(token.str_val, (x)) == 0 && match_token(TOKEN_STR))
#define assert_token_eof() assert(is_token(0))

void lex_test() {
    // Integer literal tests
    init_stream("0 18446744073709551615 0xffffffffffffffff 0x12345 042 0b1111");
    assert_token_int(0);
    assert_token_int(18446744073709551615ull);
    assert_token_int(0xffffffffffffffffull);
    assert(token.mod == TOKENMOD_HEX);
    assert_token_int(0x12345);
    assert(token.mod == TOKENMOD_OCT);
    assert_token_int(042);
    assert(token.mod == TOKENMOD_BIN);
    assert_token_int(0xF);
    assert_token_eof();
    
    // Float literal tests
    init_stream("3.14 .123 42. 3e10");
    assert_token_float(3.14);
    assert_token_float(.123);
    assert_token_float(42.);
    assert_token_float(3e10);
    assert_token_eof();
    
    // Char literal tests
    init_stream("'a' '\\n'");
    assert_token_int('a');
    assert_token_int('\n');
    assert_token_eof();
    
    // String literal tests
    init_stream("\"Foo\" \"a\\nb\"");
    assert_token_str("Foo");
    assert_token_str("a\nb");
    assert_token_eof();
    
    init_stream(": := + += ++ < <= << <<=");
    assert_token(':');
    assert_token(TOKEN_COLON_ASSIGN);
    assert_token('+');
    assert_token(TOKEN_ADD_ASSIGN);
    assert_token(TOKEN_INC);
    assert_token('<');
    assert_token(TOKEN_LTEQ);
    assert_token(TOKEN_LSHIFT);
    assert_token(TOKEN_LSHIFT_ASSIGN);
    assert_token_eof();
    
    // Generic tests
    const char *str = "XY+(XY)_HELLO1,234+994";
    init_stream(str);
    assert_token_name("XY");
    assert_token('+');
    assert_token('(');
    assert_token_name("XY");
    assert_token(')');
    assert_token_name("_HELLO1");
    assert_token(',');
    assert_token_int(234);
    assert_token('+');
    assert_token_int(994);
    assert_token_eof();
    init_stream("2147483647");
    assert_token_int(2147483647);
    assert_token_eof();
}

#undef assert_token_eof
#undef assert_token_int
#undef assert_token_name
#undef assert_token

int main(int argc, const char * argv[]) {
    buf_test();
    lex_test();
    str_intern_test();
    return 0;
}
