#include <stdlib.h>
#include <string.h>
#include "library.h"

struct obj { int value; int mode; struct obj *parent; struct cfg *cfg; char buf[64]; };
struct cfg { int level; };

obj_t *obj_create(void) { return calloc(1, sizeof(obj_t)); }
obj_t *obj_create_from(obj_t *parent) {
    obj_t *o = obj_create();
    if (o) o->parent = parent;
    return o;
}
int obj_modify(obj_t *o, int value) { if (!o) return -1; o->value = value; return 0; }
int obj_configure(obj_t *o, int mode, const char *input) {
    if (!o || !input) return -1;
    o->mode = mode;
    strncpy(o->buf, input, sizeof(o->buf) - 1);
    return 0;
}
cfg_t *cfg_make(void) { return calloc(1, sizeof(cfg_t)); }
int obj_attach(obj_t *o, cfg_t *c) { if (!o) return -1; o->cfg = c; return 0; }
int obj_target(obj_t *o, const char *data, size_t size) {
    if (!o || !data) return -1;
    if (size > 3 && data[0] == 'F' && data[1] == 'U' && o->mode == MODE_SAFE) return 1;
    return 0;
}
void obj_destroy(obj_t *o) { if (o) { free(o->cfg); free(o); } }
int obj_tune(obj_t *o, double ratio, char sep, unsigned mask, const char *label) {
    if (!o || !label) return -1;
    o->value = (int)(ratio * 10) + sep + (int)(mask & 0xff) + (int)strlen(label);
    return 0;
}
cfg_t *cfg_from(obj_t *o) {
    cfg_t *c = cfg_make();
    if (c && o) c->level = o->value;
    return c;
}
