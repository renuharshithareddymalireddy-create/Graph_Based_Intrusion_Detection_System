#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define MAX_USERS   50
#define MAX_NAME    32
#define MAX_PASS    64
#define MAX_ALERTS  200
#define HASH_SIZE   31
#define MAX_MSGS    100
#define MAX_LOGIN_EVENTS 100
typedef struct Signature {
    int id;
    char name[MAX_NAME];
    int severity;
    char description[128];
    struct Signature *next;
} Signature;
Signature *sigTable[HASH_SIZE];
unsigned int hashStr(const char *s) {
    unsigned int h = 0;
    while (*s) h = h * 31 + (unsigned char)*s++;
    return h % HASH_SIZE;
}
void initSigTable() {
    for (int i = 0; i < HASH_SIZE; i++) sigTable[i] = NULL;
}
Signature *makeSig(int id, const char *name, int sev, const char *desc) {
    Signature *s = (Signature*)malloc(sizeof(Signature));
    if (!s) {
        printf("Memory allocation failed for Signature.\n");
        exit(1);
    }
    s->id = id;
    s->severity = sev;
    strcpy(s->name, name);
    strcpy(s->description, desc);
    s->next = NULL;
    return s;
}
void insertSignature(int id, const char *name, int sev, const char *desc) {
    int idx = hashStr(name);
    Signature *s = makeSig(id, name, sev, desc);
    s->next = sigTable[idx];
    sigTable[idx] = s;
}
Signature *findSig(const char *name) {
    int idx = hashStr(name);
    Signature *cur = sigTable[idx];
    while (cur) {
        if (strcmp(cur->name, name) == 0) return cur;
        cur = cur->next;
    }
    return NULL;
}
typedef struct Alert {
    int id;
    char type[MAX_NAME];
    char attacker[MAX_NAME];
    char target[MAX_NAME];
    int severity;
    char message[128];
} Alert;
typedef struct {
    Alert heap[MAX_ALERTS];
    int size;
} AlertPQ;
void initPQ(AlertPQ *pq) { pq->size = 0; }
void swapAlert(Alert *a, Alert *b) {
    Alert t = *a; *a = *b; *b = t;
}
void heapifyUp(AlertPQ *pq, int i) {
    while (i > 0) {
        int p = (i - 1) / 2;
        if (pq->heap[p].severity >= pq->heap[i].severity) break;
        swapAlert(&pq->heap[p], &pq->heap[i]);
        i = p;
    }
}
void heapifyDown(AlertPQ *pq, int i) {
    while (1) {
        int l = 2 * i + 1;
        int r = 2 * i + 2;
        int big = i;
        if (l < pq->size && pq->heap[l].severity > pq->heap[big].severity) big = l;
        if (r < pq->size && pq->heap[r].severity > pq->heap[big].severity) big = r;
        if (big == i) break;
        swapAlert(&pq->heap[i], &pq->heap[big]);
        i = big;
    }
}
void pushAlert(AlertPQ *pq, Alert a) {
    if (pq->size >= MAX_ALERTS) {
        printf("Alert queue full. Dropping alert.\n");
        return;
    }
    pq->heap[pq->size] = a;
    heapifyUp(pq, pq->size);
    pq->size++;
}
int popAlert(AlertPQ *pq, Alert *out) {
    if (pq->size == 0) return 0;
    *out = pq->heap[0];
    pq->heap[0] = pq->heap[pq->size - 1];
    pq->size--;
    heapifyDown(pq, 0);
    return 1;
}
typedef struct {
    char username[MAX_NAME];
    char password[MAX_PASS];
} User;
User users[MAX_USERS];
int userCount = 0;
int getUserIndexByName(const char *name) {
    for (int i = 0; i < userCount; i++)
        if (strcmp(users[i].username, name) == 0)
            return i;
    return -1;
}
User *findUser(const char *name) {
    int idx = getUserIndexByName(name);
    if (idx == -1) return NULL;
    return &users[idx];
}
char currentUser[MAX_NAME] = "";
int isLoggedIn = 0;
typedef struct Node {
    int dest;
    struct Node *next;
} Node;
Node *graph[MAX_USERS];
void initGraph() {
    for (int i = 0; i < MAX_USERS; i++) graph[i] = NULL;
}
void addEdge(const char *u1, const char *u2) {
    int a = getUserIndexByName(u1);
    int b = getUserIndexByName(u2);
    if (a == -1 || b == -1) return;
    Node *n1 = (Node*)malloc(sizeof(Node));
    n1->dest = b;
    n1->next = graph[a];
    graph[a] = n1;
    Node *n2 = (Node*)malloc(sizeof(Node));
    n2->dest = a;
    n2->next = graph[b];
    graph[b] = n2;
}
void showTopology() {
    printf("\n--- Network Topology ---\n");
    if (userCount == 0) {
        printf("No users / network defined.\n");
        return;
    }
    for (int i = 0; i < userCount; i++) {
        printf("%s :", users[i].username);
        Node *p = graph[i];
        while (p) {
            printf(" -> %s", users[p->dest].username);
            p = p->next;
        }
        printf("\n");
    }
}
typedef struct {
    char type[32];   
    char details[128];
} Message;
Message inbox[MAX_USERS][MAX_MSGS];
int inboxCount[MAX_USERS];
void sendMessageToUser(const char *username, const char *type, const char *details) {
    int idx = getUserIndexByName(username);
    if (idx == -1) return;           
    if (inboxCount[idx] >= MAX_MSGS) 
        return;
    strcpy(inbox[idx][inboxCount[idx]].type, type);
    strcpy(inbox[idx][inboxCount[idx]].details, details);
    inboxCount[idx]++;
}
typedef struct {
    int id;
    char username[MAX_NAME];  
    int processed;            
} LoginEvent;
LoginEvent loginEvents[MAX_LOGIN_EVENTS];
int loginEventCount = 0;
void addLoginEvent(const char *username) {
    if (loginEventCount >= MAX_LOGIN_EVENTS) return;
    loginEvents[loginEventCount].id = rand();
    strcpy(loginEvents[loginEventCount].username, username);
    loginEvents[loginEventCount].processed = 0;
    loginEventCount++;
}
void createUsers() {
    int n;
    printf("\nEnter number of users: ");
    scanf("%d", &n);
    for (int i = 0; i < n; i++) {
        if (userCount >= MAX_USERS) {
            printf("Max user limit reached.\n");
            break;
        }
        printf("Username %d: ", i + 1);
        scanf("%s", users[userCount].username);

        printf("Password for %s: ", users[userCount].username);
        scanf("%s", users[userCount].password);
        userCount++;
    }
    int edges;
    printf("\nEnter number of connections (edges): ");
    scanf("%d", &edges);
    for (int i = 0; i < edges; i++) {
        char a[MAX_NAME], b[MAX_NAME];
        printf("Connection %d (u1 u2): ", i + 1);
        scanf("%s %s", a, b);
        addEdge(a, b);
    }
    printf("\nUsers and network created.\n");
}
void loginAttack(AlertPQ *pq) {
    char uname[MAX_NAME];
    printf("\n--- Login Attack ---\n");
    printf("Enter username to login as: ");
    scanf("%s", uname);
    User *u = findUser(uname);
    if (!u) {
        printf("User '%s' does not exist. Login blocked.\n", uname);
        return;
    }
    char guess[MAX_PASS];
    int success = 0;
    printf("\nYou have 5 attempts to guess the password.\n");
    for (int i = 1; i <= 5; i++) {
        printf("Attempt %d password: ", i);
        scanf("%s", guess);
        if (strcmp(guess, u->password) == 0) {
            success = 1;
            break;
        }
    }
    if (success) {
        printf("\nCorrect password entered, but login is NOT granted directly.\n");
        printf("A verification request has been sent to %s's inbox.\n", uname);
        addLoginEvent(uname);
        sendMessageToUser(
            uname,
            "LOGIN_ATTEMPT",
            "A login attempt used your correct password. Confirm in your inbox if it was you."
        );
    } else {
        printf("\nAll 5 attempts failed. Login blocked.\n");  
        Signature *sig = findSig("BRUTE_FORCE");
        if (sig) {
            Alert a;
            a.id = rand();
            strcpy(a.type, sig->name);
            strcpy(a.attacker, "UNKNOWN_USER");
            strcpy(a.target, uname);
            a.severity = sig->severity;
            strcpy(a.message, "Multiple wrong password attempts in login attack.");
            pushAlert(pq, a);
        }
        sendMessageToUser(
            uname,
            "LOGIN_FAIL",
            "Someone tried multiple wrong passwords to login to your account."
        );
    }
}
void accessData(AlertPQ *pq) {
    char target[MAX_NAME];
    printf("\n--- Access User Data ---\n");
    printf("Enter username whose data you want to access: ");
    scanf("%s", target);
    User *u = findUser(target);
    if (!u) {
        printf("User '%s' not found.\n", target);
        return;
    }
    if (!isLoggedIn) {
        printf("\nNo user is logged in. Access denied.\n");
        Signature *sig = findSig("UNAUTHORIZED_ACCESS");
        if (sig) {
            Alert a;
            a.id = rand();
            strcpy(a.type, sig->name);
            strcpy(a.attacker, "UNKNOWN_USER");
            strcpy(a.target, target);
            a.severity = sig->severity;
            strcpy(a.message, "Unauthorized access attempt with no logged-in user.");
            pushAlert(pq, a);
        }
        sendMessageToUser(
            target,
            "UNAUTHORIZED_ACCESS",
            "Someone tried to access your data while no user was logged in."
        );
        return;
    }
    if (strcmp(currentUser, target) == 0) {
        printf("\nUser '%s' is logged in. Access to own data allowed.\n", currentUser);
        return;
    }
    printf("\nUser '%s' attempted to access '%s' data. Access denied.\n",
           currentUser, target);
    Signature *sig = findSig("UNAUTHORIZED_ACCESS");
    if (sig) {
        Alert a;
        a.id = rand();
        strcpy(a.type, sig->name);
        strcpy(a.attacker, currentUser);
        strcpy(a.target, target);
        a.severity = sig->severity;
        strcpy(a.message, "Logged-in user attempted unauthorized data access.");
        pushAlert(pq, a);
    }
    sendMessageToUser(
        target,
        "UNAUTHORIZED_ACCESS",
        "A logged-in user tried to access your data without permission."
    );
}
void userInbox(AlertPQ *pq) {
    char uname[MAX_NAME], pass[MAX_PASS];
    printf("\n--- User Inbox ---\n");
    printf("Enter your username: ");
    scanf("%s", uname);
    printf("Enter your password: ");
    scanf("%s", pass);
    User *u = findUser(uname);
    if (!u || strcmp(u->password, pass) != 0) {
        printf("Invalid credentials. Cannot open inbox.\n");
        return;
    }
    int idx = getUserIndexByName(uname);
    printf("\nMessages for %s:\n", uname);
    if (inboxCount[idx] == 0) {
        printf("No messages.\n");
    } else {
        for (int i = 0; i < inboxCount[idx]; i++) {
            printf("\nMessage %d:\n", i + 1);
            printf("Type   : %s\n", inbox[idx][i].type);
            printf("Details: %s\n", inbox[idx][i].details);
        }
    }
    printf("\nChecking pending login verification events for %s...\n", uname);
    int anyPending = 0;
    for (int i = 0; i < loginEventCount; i++) {
        if (!loginEvents[i].processed &&
            strcmp(loginEvents[i].username, uname) == 0) {
            anyPending = 1;
            printf("\nLogin Event ID: %d\n", loginEvents[i].id);
            printf("Someone used your correct password to attempt a login.\n");
            printf("Was this login you? (yes/no): ");
            char ans[8];
            scanf("%s", ans);
            if (strcmp(ans, "yes") == 0) {
                printf("Login attempt approved.\n");
                strcpy(currentUser, uname);
                isLoggedIn = 1;
                printf("User '%s' is now marked as logged in.\n", currentUser);
            } else {
                printf("Login attempt denied. Credential theft alert generated.\n");
                Signature *sig = findSig("CREDENTIAL_THEFT");
                if (sig) {
                    Alert a;
                    a.id = rand();
                    strcpy(a.type, sig->name);
                    strcpy(a.attacker, "UNKNOWN_USER");
                    strcpy(a.target, uname);
                    a.severity = sig->severity;
                    strcpy(a.message, "User denied correct-password login attempt.");
                    pushAlert(pq, a);
                }
            }
            loginEvents[i].processed = 1;
        }
    }
    if (!anyPending) {
        printf("No pending login events for you.\n");
    }
}
void processAlerts(AlertPQ *pq) {
    printf("\n--- Alert Log ---\n");
    if (pq->size == 0) {
        printf("No alerts.\n");
        return;
    }
    Alert a;
    while (popAlert(pq, &a)) {
        printf("\nAlert ID : %d\n", a.id);
        printf("Type     : %s\n", a.type);
        printf("Severity : %d\n", a.severity);
        printf("Attacker : %s\n", a.attacker);
        printf("Target   : %s\n", a.target);
        printf("Message  : %s\n", a.message);
    }
}
int main() {
    srand((unsigned int)time(NULL));
    initGraph();
    initSigTable();
    insertSignature(1, "CREDENTIAL_THEFT",    9, "User denied a correct-password login.");
    insertSignature(2, "UNAUTHORIZED_ACCESS",10, "Unauthorized attempt to access user data.");
    insertSignature(3, "BRUTE_FORCE",        7, "Multiple wrong password guesses in login.");
    AlertPQ pq;
    initPQ(&pq);
    int ch;
    while (1) {
        printf("\n=== IDS MENU ===\n");
        printf("1. Create Network\n");
        printf("2. Show Network Topology\n");
        printf("3. Login Attack (5 attempts)\n");
        printf("4. Access User Data\n");
        printf("5. Process Alerts\n");
        printf("6. User Inbox (check messages + approve login)\n");
        printf("0. Exit\n");
        printf("Choice: ");
        if (scanf("%d", &ch) != 1) break;
        switch (ch) {
            case 1: createUsers();      break;
            case 2: showTopology();     break;
            case 3: loginAttack(&pq);   break;
            case 4: accessData(&pq);    break;
            case 5: processAlerts(&pq); break;
            case 6: userInbox(&pq);     break;
            case 0: return 0;
            default: printf("Invalid choice.\n");
        }
    }
    return 0;
}