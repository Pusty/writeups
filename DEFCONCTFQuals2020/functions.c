#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

struct tree{ // sizeof(0x20)

    uint32_t character;
    uint32_t value1;
    uint32_t value2;
    struct tree* p1;
    struct tree* p2;
};

struct tree* appendElement(struct tree* l, char c);
struct tree* create(char c);
struct tree* modify(struct tree* l);
struct tree* modify2(struct tree* l);


void printTreeSub(struct tree* l) {
    if(l == 0) {
        printf("NULL");
        return;
    }
    printf("L(0x%02X, %d, %d) -> {", l->character, l->value1, l->value2);
    printTreeSub(l->p1);
    printf(" , ");
    printTreeSub(l->p2);
    printf("}");
}

void printTree(struct tree* l) {
    printTreeSub(l);
    printf("\n");
}

int main(char** args) {

    puts("Testing...");
    struct tree* var_8 = 0;
    var_8 = appendElement(var_8, 'O');
    printTree(var_8);
    var_8 = appendElement(var_8, 'O');
    printTree(var_8);
    var_8 = appendElement(var_8, 'O');
    printTree(var_8);
    var_8 = appendElement(var_8, '{');
    printTree(var_8);
    var_8 = appendElement(var_8, 't');
    printTree(var_8);
    var_8 = appendElement(var_8, 'e');
    printTree(var_8);
    var_8 = appendElement(var_8, 's');
    printTree(var_8);
    var_8 = appendElement(var_8, 't');
    printTree(var_8);
    var_8 = appendElement(var_8, '}');
    printTree(var_8);
    
    return 0;
}



// d670e25f0b1e4b298321e687f777ec14
struct tree* appendElement(struct tree* l, char c) {
    if(l == 0) {
        return create(c);
    }else {
        if(c == l->character) {
            l->value1 = l->value1 + 1;
            l = modify(l);
            l = modify2(l);
        }else {
            if(c >= l->character) {
                l->p2 = appendElement(l->p2, c);
                l = modify(l);
                l = modify2(l);
                return l;
            }else {
                l->p1 = appendElement(l->p1, c);
                l = modify(l);
                l = modify2(l);
                return l;
            }
        }
    }
}

// b58310a1d83b616fca1491b8ddaa4051
struct tree* create(char c) {
    struct tree* thing = (struct tree*)malloc(sizeof(struct tree));
    thing->character = c;
    thing->value1 = 1;
    thing->value2 = 1;
    thing->p1 = 0;
    thing->p2 = 0;
    return thing;
}

// 83be5e65d5010b6ce1fd4da060e07888
struct tree* modify(struct tree* l) {
    if(l->p1 == 0) return l;
    if(l->p1->value2 != l->value2) return l;
    struct tree* l2 = l->p1;
    l->p1 = l2->p2;
    l2->p2 = l;
    return l2;
}

// 1f7aa429199eac8a7c6017e9e57df7fc
struct tree* modify2(struct tree* l) {
    if(l->p2 == 0) return l;
    if(l->p2->p2 == 0) return l;
    if(l->p2->p2->value2 != l->value2) return l;
    struct tree* l2 = l->p2;
    l->p2 = l2->p1;
    l2->p1 = l;
    l2->value2 = l2->value2 + 1;
    return l2;
}
