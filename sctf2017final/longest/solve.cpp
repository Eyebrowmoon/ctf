#include <iostream>
#include <cassert>
#include <vector>
#include <algorithm>
#include <cstring>

using namespace std;

char s[130000];

bool LessThan(const char* p1, const char* p2) {
    return strcmp(p1, p2) < 0;
}
 
void FindLongestDup(const char* str) {
    assert(str);
 
    const char* p = str;
    vector<const char*> vec; //suffix array pointers
    while (*p != 0) {
    
        vec.push_back(p++);
        
    }    
 
    sort(vec.begin(), vec.end(), LessThan);
 
    int curmax = 0;
    
    const char* pmax = str;
    
    for (int i = 0; i < vec.size() - 1; ++i) {
    
        int len = 0;
        const char* piter1 = vec[i];
        const char* piter2 = vec[i+1];
        while (*piter1 != 0 && *piter2 != 0 && *piter1 == *piter2) { //two prefix overlap
        
            piter1++, piter2++;
            len++;
        }
 
        if (len > curmax) {
        
            pmax = vec[i];
            curmax = len;
        }
    }
 
    for (int i = 0; i < curmax; ++i) {
    
        cout<<*pmax++;
        
    }    
}

int main() {
    cin.getline(s, sizeof(s));
    FindLongestDup(s);
    return 0;
}

