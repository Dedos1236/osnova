#include "skip_list.h"
#include <cstdlib>

namespace nit::osnova::ds {

SkipList::SkipList() : current_level_(0) {
    head_ = new Node("", "", MAX_LEVEL);
}

SkipList::~SkipList() {
    Node* current = head_;
    while (current != nullptr) {
        Node* next = current->forward[0];
        delete current;
        current = next;
    }
}

int SkipList::random_level() const {
    int level = 0;
    while ((rand() & 0xFFFF) < (0xFFFF / 2) && level < MAX_LEVEL) {
        level++;
    }
    return level;
}

void SkipList::insert(const std::string& key, const std::string& value) {
    std::vector<Node*> update(MAX_LEVEL + 1, nullptr);
    Node* current = head_;

    for (int i = current_level_; i >= 0; --i) {
        while (current->forward[i] != nullptr && current->forward[i]->key < key) {
            current = current->forward[i];
        }
        update[i] = current;
    }

    current = current->forward[0];

    if (current != nullptr && current->key == key) {
        current->value = value;
    } else {
        int rlevel = random_level();
        if (rlevel > current_level_) {
            for (int i = current_level_ + 1; i <= rlevel; ++i) {
                update[i] = head_;
            }
            current_level_ = rlevel;
        }

        Node* n = new Node(key, value, rlevel);
        for (int i = 0; i <= rlevel; ++i) {
            n->forward[i] = update[i]->forward[i];
            update[i]->forward[i] = n;
        }
    }
}

bool SkipList::search(const std::string& key, std::string& out_value) const {
    Node* current = head_;
    for (int i = current_level_; i >= 0; --i) {
        while (current->forward[i] != nullptr && current->forward[i]->key < key) {
            current = current->forward[i];
        }
    }
    
    current = current->forward[0];
    if (current != nullptr && current->key == key) {
        out_value = current->value;
        return true;
    }
    return false;
}

void SkipList::erase(const std::string& key) {
    std::vector<Node*> update(MAX_LEVEL + 1, nullptr);
    Node* current = head_;

    for (int i = current_level_; i >= 0; --i) {
        while (current->forward[i] != nullptr && current->forward[i]->key < key) {
            current = current->forward[i];
        }
        update[i] = current;
    }

    current = current->forward[0];

    if (current != nullptr && current->key == key) {
        for (int i = 0; i <= current_level_; ++i) {
            if (update[i]->forward[i] != current) break;
            update[i]->forward[i] = current->forward[i];
        }
        
        while (current_level_ > 0 && head_->forward[current_level_] == nullptr) {
            current_level_--;
        }
        delete current;
    }
}

} // namespace nit::osnova::ds
