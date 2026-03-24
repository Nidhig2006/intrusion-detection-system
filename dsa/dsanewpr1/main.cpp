#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
using namespace std;

#define MAX_FAILS 10
#define WINDOW 30000
#define MAX_RESTRICTED 3
#define MAX_USERS 100
#define MAX_LOGS 1000

string restrictedPaths[MAX_RESTRICTED] = {"/admin", "/root", "/system"};

struct LogEvent {
    string user;
    string action;
    long long timestamp;
};

// -------- Circular Queue to track recent failures --------
class CircularQueue {
public:
    long long arr[MAX_FAILS];
    int front, rear, count;

    CircularQueue() {
        front = rear = count = 0;
    }

    void enqueue(long long t) {
        if (count == MAX_FAILS) {
            front = (front + 1) % MAX_FAILS;
            count--;
        }
        arr[rear] = t;
        rear = (rear + 1) % MAX_FAILS;
        count++;
    }

    int getCount(long long window, long long current) {
        int c = 0;
        for (int i = 0; i < count; i++) {
            int index = (front + i) % MAX_FAILS;
            if (current - arr[index] <= window)
                c++;
        }
        return c;
    }
};

// -------- BST Node for each User --------
struct UserNode {
    string username;
    int score;
    CircularQueue q;
    UserNode* left;
    UserNode* right;

    UserNode(string name) {
        username = name;
        score = 0;
        left = right = nullptr;
    }
};

// -------- BST Operations --------
UserNode* insertUser(UserNode* root, string username) {
    if (!root)
        return new UserNode(username);
    if (username < root->username)
        root->left = insertUser(root->left, username);
    else if (username > root->username)
        root->right = insertUser(root->right, username);
    return root;
}

UserNode* findUser(UserNode* root, string username) {
    if (!root)
        return nullptr;
    if (root->username == username)
        return root;
    if (username < root->username)
        return findUser(root->left, username);
    return findUser(root->right, username);
}

// -------- Check if path is restricted --------
bool isRestricted(string path) {
    for (int i = 0; i < MAX_RESTRICTED; i++) {
        if (path.rfind(restrictedPaths[i], 0) == 0)
            return true;
    }
    return false;
}

// -------- Read logs from file --------
int readLogs(LogEvent logs[], int maxLogs, string filename) {
    ifstream file(filename);
    if (!file.is_open()) {
        cout << "Error opening file: " << filename << endl;
        return 0;
    }

    string line;
    int count = 0;
    while (getline(file, line) && count < maxLogs) {
        if (line.empty()) continue;
        stringstream ss(line);
        string user, action, tstr;
        getline(ss, user, ',');
        getline(ss, action, ',');
        getline(ss, tstr, ',');
        if (!user.empty() && !action.empty() && !tstr.empty()) {
            logs[count].user = user;
            logs[count].action = action;
            logs[count].timestamp = stoll(tstr);
            count++;
        }
    }
    file.close();
    return count;
}

// -------- Inorder Traversal to store usernames and scores --------
void inorder(UserNode* root, string names[], int scores[], int &index) {
    if (!root) return;
    inorder(root->left, names, scores, index);
    names[index] = root->username;
    scores[index] = root->score;
    index++;
    inorder(root->right, names, scores, index);
}

// -------- Bubble Sort by score --------
void sortByScore(string names[], int scores[], int n) {
    for (int i = 0; i < n - 1; i++) {
        for (int j = i + 1; j < n; j++) {
            if (scores[j] > scores[i]) {
                swap(scores[j], scores[i]);
                swap(names[j], names[i]);
            }
        }
    }
}

// -------- Main Program --------
int main() {
    LogEvent logs[MAX_LOGS];
    int logCount = readLogs(logs, MAX_LOGS, "logs.txt");
    cout << "Read " << logCount << " log entries.\n";

    UserNode* root = nullptr;

    // Process all logs
    for (int i = 0; i < logCount; i++) {
        string user = logs[i].user;
        string action = logs[i].action;
        long long time = logs[i].timestamp;

        if (!findUser(root, user))
            root = insertUser(root, user);

        UserNode* u = findUser(root, user);

        // Count failed login attempts
        if (action.find("FAILED_LOGIN") == 0) {
            u->q.enqueue(time);
            int fails = u->q.getCount(WINDOW, time);
            if (fails >= 3)
                u->score += 5;
        }

        // Check restricted access
        if (isRestricted(action))
            u->score += 10;
    }

    // Collect data from BST
    string names[MAX_USERS];
    int scores[MAX_USERS];
    int n = 0;
    inorder(root, names, scores, n);

    // Sort by suspicious score
    sortByScore(names, scores, n);

    // Print top 5 users
    cout << "\n=== Top 5 Suspicious Users ===\n";
    int limit = (n < 5) ? n : 5;
    for (int i = 0; i < limit; i++) {
        cout << names[i] << " -> Score: " << scores[i] << endl;
    }

    return 0;
}
