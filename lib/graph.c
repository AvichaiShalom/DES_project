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



//working with clebsch graph

// פונקציה לערבוב רשימת שכנים
void shuffle(int array[], int n) {
    int i, j, temp;
    for (i = n - 1; i > 0; i--) {
        j = rand() % (i + 1);
        temp = array[i];
        array[i] = array[j];
        array[j] = temp;
    }
}

// בקטרקינג למציאת מסלול בגרף קלבש
int backtrack(int visited[V], int path[V], int current, int step) {
    // יצירת עותק של רשימת השכנים וערבובה
    int neighbors[CLEBSCH_NEIGHBORS];
    int i;
    int next;
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
    if (step == V) return true; // אם עברנו בכל הצמתים

    for (i = 0; i < CLEBSCH_NEIGHBORS; i++) {
        neighbors[i] = clebsch_adj_lst[current][i];
    }
    shuffle(neighbors, CLEBSCH_NEIGHBORS); // ערבוב השכנים כדי להוסיף רנדומליות

    // חיפוש צומת שלא ביקרנו בו עדיין
    for (i = 0; i < CLEBSCH_NEIGHBORS; i++) {
        next = neighbors[i];
        if (!visited[next]) {
            visited[next] = 1;
            path[step] = next;
            if (backtrack(visited, path, next, step + 1)) return true;
            visited[next] = 0; // חזרה אחורה אם לא הצלחנו
        }
    }

    return false;
}

// פונקציה להפקת מסלול רנדומלי
void generate_path(int path[V]) {
    int start;
    int visited[V] = {0};
    
    // בוחרים צומת התחלתי שונה כל פעם
    start = rand() % V;
    visited[start] = 1;
    path[0] = start;

    if (!backtrack(visited, path, start, 1)) {
        perror("could not generate sBoxes");
        exit(1);
    }
}

// פונקציה להפקת כל המסלולים לכל S-Box
void generate_sboxes(int sboxes[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS]) {
    for (int i = 0; i < S_BOXES_COUNT; i++) { // יצירת 8 תיבות S-Box
        for (int j = 0; j < S_BOXES_ROWS; j++) { // לכל S-Box יש 4 מסלולים
            generate_path(sboxes[i][j]); // מייצר מסלול רנדומלי
        }
    }
}

void print_sboxes(int sboxes[S_BOXES_COUNT][S_BOXES_ROWS][S_BOXES_COLS]) {
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



//working with AGraph

void set_weight_AGraph_adj_mat(int AGraph_adj_lst[V][AGRAPH_NEIGHBORS], int AGraph_adj_mat[V][V]) {
    int r, c;
    for (r = 0; r < V; r++) {
        for (c = 0; c < V; c++) {
            AGraph_adj_mat[r][c] = -1;
        }
    }
    for (r = 0; r < V; r++) {
        for (c = 0; c < AGRAPH_NEIGHBORS; c++) {
            AGraph_adj_mat[r][AGraph_adj_lst[r][c]] = rand() % 101;
        }
    }
}


int dijkstra_path(int graph[V][V], int start, int end, int path[V]) {
    int dist[V];         // dist[i] - the shortest distance found so far from start to i
    int prev[V];         // prev[i] - the previous node we came from to get to i in the shortest path
    int min, u, v, count, weight;
    int current, path_len;
    int temp, i;
    int visited[V] = {0}; // marks whether a node has been processed or not

    // Initialization of all nodes
    for (int i = 0; i < V; i++) {
        dist[i] = INF;    // At first, there is no path to any node, so distance is infinite
        prev[i] = -1;     // We haven't come from anywhere yet
    }

    dist[start] = 0; // For the start node, the distance is 0

    // Run the algorithm V-1 times (this is enough to find the shortest path for all nodes)
    for (count = 0; count < V - 1; count++) {
        // Find the unvisited node with the smallest distance
        min = INF;
        u = -1;
        for (v = 0; v < V; v++) {
            if (!visited[v] && dist[v] < min) {
                min = dist[v];
                u = v;
            }
        }

        if (u == -1) break; // If no node can be reached, stop the process

        visited[u] = 1; // Mark the current node as processed

        // Now check all neighbors of node u
        for (v = 0; v < V; v++) {
            weight = graph[u][v]; // Check if there's an edge from u to v
            if (weight != -1 && !visited[v] && dist[u] + weight < dist[v]) {
                // If there is an edge, v is unvisited, and the new path is shorter than the previous one
                dist[v] = dist[u] + weight; // Update the shortest distance to v
                prev[v] = u; // Store that we came to v from u in the shortest path
            }
        }
    }

    // Reconstruct the path from the end to the start
    current = end;
    path_len = 0;

    while (current != -1) {
        path[path_len++] = current;  // Add the current node to the path
        current = prev[current];     // Move to the previous node in the path
    }

    // Now the path is reversed (end → start), so we reverse it
    for (i = 0; i < path_len / 2; i++) {
        temp = path[i];
        path[i] = path[path_len - i - 1];
        path[path_len - i - 1] = temp;
    }

    return path_len; // Return the length of the path
}

void complexify_subkeys(uint64_t subkeys[V]) {
    int AGraph_adj_mat[V][V];
    int path[V];
    int path_length;
    int i, j;
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
    uint64_t new_subkeys[V] = {0};
    for (i = 0; i < 16; i++) {
        set_weight_AGraph_adj_mat(AGraph_adj_lst, AGraph_adj_mat);// ממשקל מחד את הגרף
        path_length = dijkstra_path(AGraph_adj_mat, i, (16 + i - 1) % 16, path);
        for (j = 0; j < path_length; j++) {
            new_subkeys[i] ^= subkeys[path[j]];
        }
    }
    for (i = 0; i < V; i++) {
        subkeys[i] = new_subkeys[i];
    }
}

#include <stdio.h>
#include <inttypes.h>

void print_subkeys(uint64_t* subkeys) {
    printf("Subkeys:\n");
    for (int i = 0; i < 16; i++) {
        printf("Subkey %d: 0x%016" PRIx64 "\n", i + 1, subkeys[i]);
    }
}