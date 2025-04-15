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
/*
int** get_AGraph_adj_lst() {
    int AGraph_adj_lst[16][2] = {
        {1, 2},
        {2, 3},
        {3, 4},
        {4, 5},
        {5, 6},
        {6, 7},
        {7, 8},
        {8, 9},
        {9, 10},
        {10, 11},
        {11, 12},
        {12, 13},
        {13, 14},
        {14, 15},
        {15, 0}
    };
    return AGraph_adj_lst;
}


int** get_clebsch_adj_lst() {
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
    return clebsch_adj_lst;
}
*/

typedef struct Graph {
    int id;
    struct Graph* neighbors[CLEBSCH_NEIGHBORS];
} Graph;

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

// בקטרקינג למציאת מסלול בגרף קלבש
static int backtrack(Graph *nodes, int visited[V], int path[V], int current, int step) {
    // אם עברנו בכל הצמתים, אז מצאנו מסלול
    if (step == V) return true;

    // עבור כל שכן של הצומת הנוכחי
    for (int i = 0; i < CLEBSCH_NEIGHBORS; i++) {
        int next = nodes[current].neighbors[i]->id;  // ניגש לשכן מתוך המצביע

        // אם השכן לא בוקר עדיין
        if (!visited[next]) {
            visited[next] = 1;  // סימן את השכן כביקרנו בו
            path[step] = next;  // עדכון המסלול
            if (backtrack(nodes, visited, path, next, step + 1)) return true; // חזרה אם הצלחנו
            visited[next] = 0;  // חזרה אחורה אם לא הצלחנו
        }
    }

    return false;  // אם לא מצאנו מסלול
}

static int **allocate_matrix(int rows, int cols) {
    int **matrix = malloc(rows * sizeof(int *));
    if (!matrix) {
        perror("Failed to allocate row pointers");
        exit(1);
    }
    for (int i = 0; i < rows; i++) {
        matrix[i] = malloc(cols * sizeof(int));
        if (!matrix[i]) {
            perror("Failed to allocate row");
            exit(1);
        }
    }
    return matrix;
}

static void free_matrix(int **matrix, int rows) {
    for (int i = 0; i < rows; i++) {
        free(matrix[i]);
    }
    free(matrix);
}

// מסלול מינימלי שעובר בכל צומת בדיוק פעם אחת, בלי לחזור להתחלה
static int hamiltonian_path_dp(Graph *nodes, int start, int path[V]) {
    int **dp = allocate_matrix(1 << V, V);
    int **parent = allocate_matrix(1 << V, V);

    for (int i = 0; i < (1 << V); i++)
        for (int j = 0; j < V; j++) {
            dp[i][j] = INT_MAX;
            parent[i][j] = -1;
        }

    dp[1 << start][start] = 0;


    for (int mask = 0; mask < (1 << V); mask++) {
        for (int u = 0; u < V; u++) {
            if (!(mask & (1 << u)) || dp[mask][u] == INT_MAX) continue;

            for (int i = 0; i < CLEBSCH_NEIGHBORS; i++) {
                int v = nodes[u].neighbors[i]->id;
                if (mask & (1 << v)) continue;

                int next_mask = mask | (1 << v);
                if (dp[next_mask][v] > dp[mask][u] + 1) {
                    dp[next_mask][v] = dp[mask][u] + 1;
                    parent[next_mask][v] = u;
                }
            }
        }
    }

    // מחפש את הסיום עם המסלול הקצר ביותר
    int end = -1;
    int best_cost = INT_MAX;
    for (int i = 0; i < V; i++) {
        if (i != start && dp[(1 << V) - 1][i] < best_cost) {
            best_cost = dp[(1 << V) - 1][i];
            end = i;
        }
    }

    if (end == -1) {
        return 0; // אין מסלול
    }

    // משחזר את המסלול
    int mask = (1 << V) - 1;
    int idx = V - 1;
    while (end != -1) {
        path[idx--] = end;
        int prev = parent[mask][end];
        mask ^= (1 << end);
        end = prev;
    }

    free_matrix(dp, 1 << V);
    free_matrix(parent, 1 << V);
    return 1; // הצלחה
}

// פונקציה להפקת מסלול רנדומלי
static void generate_path(Graph *nodes, int path[V]) {
    int start;
    int i;
    int visited[V] = {0};
    
    // בוחרים צומת התחלתי שונה כל פעם
    start = rand() % V;
    visited[start] = 1;
    path[0] = start;

    for (i = 0; i < V; i++) {
        shuffle(nodes[i].neighbors, CLEBSCH_NEIGHBORS);
    }

    if (!backtrack(nodes, visited, path, start, 1)) {
        perror("could not generate sBoxes");
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
    for (int i = 0; i < S_BOXES_COUNT; i++) { // יצירת 8 תיבות S-Box
        for (int j = 0; j < S_BOXES_ROWS; j++) { // לכל S-Box יש 4 מסלולים
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