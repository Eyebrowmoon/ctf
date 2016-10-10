
struct poison {
  char name[48];
  char description[200];
};

void init (void);

int select_menu (void);
int select_page (void);

void read_poison (struct poison *p);
void write_poison (struct poison *p);

void insert_poison (void);
void modify_poison (void);
void dump_poison (void);
void remove_poison (void);
void list_all (void);
