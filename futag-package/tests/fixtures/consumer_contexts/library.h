/* Synthetic library API used by the consumer-context fixtures.
 * Each case under cases/ is a tiny consumer of this API. */
#include <stddef.h>

typedef struct obj obj_t;
typedef struct cfg cfg_t;

enum mode { MODE_FAST = 0, MODE_SAFE = 1 };

obj_t *obj_create(void);
obj_t *obj_create_from(obj_t *parent);
int obj_modify(obj_t *o, int value);
int obj_configure(obj_t *o, int mode, const char *input);
cfg_t *cfg_make(void);
int obj_attach(obj_t *o, cfg_t *c);
cfg_t *cfg_from(obj_t *o);
int obj_target(obj_t *o, const char *data, size_t size);
void obj_destroy(obj_t *o);
int obj_tune(obj_t *o, double ratio, char sep, unsigned mask, const char *label);

/* C++ overloads (case 08): same name, different arity. */
#ifdef __cplusplus
int process(obj_t *o, int a);
int process(obj_t *o, int a, int b);
#endif
