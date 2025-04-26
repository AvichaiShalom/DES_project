#include <stdlib.h>
#include <stdint.h>
#include "../include/graph.h"

/*
int clebsch_adj_mat[16][16] = {
    {0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0},
    {1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0, 0},
    {0, 1, 0, 1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 0},
    {0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0},
    {1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 0, 0},
    {0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 1},
    {0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1},
    {1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1},
    {0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1},
    {1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 1},
    {0, 0, 0, 0, 1, 1, 0, 0, 0, 1, 0, 0, 1, 1, 0, 0},
    {1, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0},
    {0, 1, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 0, 1, 0},
    {0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 1},
    {0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 1, 0, 0, 0},
    {0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0}
};
*/


typedef struct Graph {
    int id;
    struct Graph* neighbors[CLEBSCH_NEIGHBORS];
} Graph;

// מאתחל את הגרף
static void init_graph(Graph *nodes, int adjacency[V][CLEBSCH_NEIGHBORS]) {
    int i, j;
    for (i = 0; i < V; i++) {
        nodes[i].id = i;
        for (j = 0; j < CLEBSCH_NEIGHBORS; j++) {
            nodes[i].neighbors[j] = &nodes[adjacency[i][j]];
        }
    }
}

// פונקציה לערבוב רשימת שכנים
static void shuffle(Graph* array[], int n) {
    int i, j;
    Graph* temp;
    for (i = n - 1; i > 0; i--) {
        j = rand() % (i + 1);
        temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

// בקטרקינג למציאת מסלול המילטוני
static int backtrack(Graph *nodes, int visited[V], int path[V], int current, int step) {
    int i;
    int next;
    // נמצא מסלול
    if (step == V) return 1;

    // עבור כל שכן של הצומת הנוכחי
    for (i = 0; i < CLEBSCH_NEIGHBORS; i++) {
        next = nodes[current].neighbors[i]->id;

        // אם השכן לא בוקר עדיין
        if (!visited[next]) {
            visited[next] = 1;
            path[step] = next; 
            if (backtrack(nodes, visited, path, next, step + 1)) return 1;// נמצא מסלול
            visited[next] = 0;  // חזרה אחורה אם לא הצלחנו
        }
    }

    return 0;  // לא נמצע מסלול
}

// פונקציה להפקת מסלול המילטוני רנדומלי
static void generate_path(Graph *nodes, int path[V]) {
    int start;
    int i;
    int visited[V] = {0};
    
    // בוחרים צומת התחלתי שונה כל פעם
    start = rand() % V;
    visited[start] = 1;
    path[0] = start;

    // עובר על כל צומת, בעבור כל צומת מערבב את סדר השכנים
    for (i = 0; i < V; i++) {
        shuffle(nodes[i].neighbors, CLEBSCH_NEIGHBORS);
    }

    if (!backtrack(nodes, visited, path, start, 1)) {
        perror("could not generate sBoxes");// על הגרף שלי זה לא אמור להגיע לכאן אף פעם
        exit(1);
    }
}

// פונקציה להפקת כל המסלולים לכל S-Box
void generate_sboxes(int sboxes[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS]) {
    Graph nodes[V];
    int clebsch_adj_lst[16][5] = {
        {1, 4, 7, 9, 11},
        {0, 2, 5, 8, 12},
        {1, 3, 6, 9, 13},
        {2, 4, 5, 7, 14},
        {0, 3, 6, 8, 10},
        {1, 3, 10, 11, 15},
        {2, 4, 11, 12, 15},
        {0, 3, 12, 13, 15},
        {1, 4, 13, 14, 15},
        {0, 2, 10, 14, 15},
        {4, 5, 9, 12, 13},
        {0, 5, 6, 13, 14},
        {1, 6, 7, 10, 14},
        {2, 7, 8, 10, 11},
        {3, 8, 9, 11, 12},
        {5, 6, 7, 8, 9}
    };
    init_graph(nodes, clebsch_adj_lst);
    for (int i = 0; i < S_BOXES_COUNT; i++) { // 8 תיבות
        for (int j = 0; j < S_BOXES_ROWS; j++) { // 4 שורות
            generate_path(nodes, sboxes[i][j]); // מייצר מסלול רנדומלי
        }
    }
}
/*
static void print_sboxes(int sboxes[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS]) {
    for (int i = 0; i < S_BOXES_COUNT; i++) {
        printf("S-Box %d:\n", i + 1);
        for (int row = 0; row < S_BOXES_ROWS; row++) {
            for (int col = 0; col < S_BOXES_COLS; col++) {
                printf("%2d ", sboxes[i][row][col]);
            }
            printf("\n");
        }
        printf("\n");
    }
}
*/