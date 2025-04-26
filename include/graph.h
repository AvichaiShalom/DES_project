#ifndef graphs
#define graphs

#include <stdint.h>

#define V 16
#define AGRAPH_NEIGHBORS 2
#define CLEBSCH_NEIGHBORS 5

#define S_BOXES_COUNT 8
#define S_BOXES_ROWS 4
#define S_BOXES_COLS 16

void generate_sboxes(int sboxes[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS]);

#endif