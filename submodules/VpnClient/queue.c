#include <stdlib.h>
#include "queue.h"

void queue_init(QUEUE *q) {
	q->frnt = NULL;
	q->tail = NULL;
}

void queue_push_back(QUEUE *q, void * f) {
	struct node * back = (struct node *) malloc (sizeof(struct node));
	back->field = f;
	back->next = NULL;

	if (q->frnt == NULL && q->tail == NULL) {
		q->frnt = q->tail = back;
	} else {
		q->tail->next = back;
		q->tail = back;
	}
}

int queue_is_empty(QUEUE *q) {
  if(q->frnt == NULL)
    return 1;
  else
    return 0;
}

void * queue_pop_front(QUEUE *q) {
	if (queue_is_empty(q) == 1)
		return NULL;
	else {
		void * value = q->frnt->field;
		struct node * temp = q->frnt;
		q->frnt = q->frnt->next;
		free(temp);
		return value;
	}
}

void * queue_top(QUEUE *q) {
	if (queue_is_empty(q) == 1)
		return NULL;
	else {
		return q->frnt->field;
	}
}

void * queue_back(QUEUE *q) {
	if (queue_is_empty(q) == 1)
		return NULL;
	else {
		return q->tail->field;
	}
}












