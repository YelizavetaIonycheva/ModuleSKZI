#ifndef QUEUE_H_
#define QUEUE_H_

struct node {
	void * field;
	struct node * next;
};

typedef struct queue {
	struct node * frnt;
	struct node * tail;
} QUEUE;

void queue_init(QUEUE *q);
void queue_push_back(QUEUE *q, void * f);
int queue_is_empty(QUEUE *q);
void * queue_pop_front(QUEUE *q);
void * queue_top(QUEUE *q);
void * queue_back(QUEUE *q);


#endif

