#include "poison.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct poison *poisons[32];

int main (int argc, char *argv[]) {
  int choice = 0;

  init ();

  while (1) {
    choice = select_menu ();

    switch (choice) {
      case 1:
        insert_poison ();
        break;
      case 2:
        modify_poison ();
        break;
      case 3:
        dump_poison ();
        break;
      case 4:
        remove_poison ();
        break;
      case 5:
        list_all ();
        break;
      default:
        exit (0);  
    }
  }

  return 0;  
}

void init (void) {
  int i;
  
  for (i = 0; i < 32; i++)
    poisons[i] = NULL;  
}

int select_menu (void) {
  int choice = 6;
  
  puts ("--- Poison Research Note ---");  
  puts ("1. Insert");
  puts ("2. Modify");
  puts ("3. Read");
  puts ("4. Remove");
  puts ("5. List All");
  puts ("6. Exit");
  printf ("> ");

  scanf("%d", &choice);

  return choice;
}

int select_page (void) {
  int page = 0;
  
  printf ("Page number (0 ~ 31): ");
  scanf("%d", &page);

  if (page < 0 || page > 31) {
    puts ("Invalid page");
    return -1;
  }

  return page;
}

void read_poison (struct poison *p) {
  memset (p, 0, sizeof (struct poison));

  printf ("Name: "); 
  scanf ("%48s", p->name);
  fflush (stdin);

  printf ("Description: ");
  scanf ("%200s", p->description);
  fflush (stdin);
}

void write_poison (struct poison *p) {
  printf ("Name: %s\n", p->name);
  printf ("Description: %s\n", p->description); 
}

void insert_poison (void) {
  int page = select_page ();
  struct poison *p = (struct poison *) malloc (sizeof (struct poison));

  if (page == -1)
    return;

  if (poisons[page]) {
    printf("Page %d is not empty.\n", page);
    return;
  }

  poisons[page] = p;

  read_poison (p);
}

void modify_poison (void) {
  int page = select_page ();

  if (page == -1)
    return;

  if (!poisons[page]) {
    printf ("Page %d is empty.\n", page);
    return;
  }

  read_poison (poisons[page]);
}

void dump_poison (void) {
  int page = select_page ();
 
  if (page == -1)
    return;

  if (!poisons[page]) {
    printf ("Page %d is empty.\n", page);
    return;
  }
 
  write_poison (poisons[page]);
}

void remove_poison (void) {
  int page = select_page ();
 
  if (page == -1)
    return;

  if (!poisons[page]) {
    printf ("Page %d is empty.\n", page);
    return;
  }
 
  free (poisons[page]);

  poisons[page] = NULL;
}

void list_all (void) {
  int page;
  
  for (page = 0; page < 32; page++)
    if (poisons[page]) {
      printf ("- Page %d -\n", page);
      write_poison (poisons[page]);
      printf ("\n");
    }
}
