#include <fcntl.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h> // termios, TCSANOW, ECHO, ICANON
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>

const char *sysname = "shellish";

enum return_codes {
  SUCCESS = 0,
  EXIT = 1,
  UNKNOWN = 2,
};

struct command_t {
  char *name;
  bool background;
  bool auto_complete;
  int arg_count;
  char **args;
  char *redirects[3];     // in/out redirection
  struct command_t *next; // for piping
};


/**
 * Prints a command struct
 * @param struct command_t *
 */
void print_command(struct command_t *command) {
  int i = 0;
  printf("Command: <%s>\n", command->name);
  printf("\tIs Background: %s\n", command->background ? "yes" : "no");
  printf("\tNeeds Auto-complete: %s\n", command->auto_complete ? "yes" : "no");
  printf("\tRedirects:\n");
  for (i = 0; i < 3; i++)
    printf("\t\t%d: %s\n", i,
           command->redirects[i] ? command->redirects[i] : "N/A");
  printf("\tArguments (%d):\n", command->arg_count);
  for (i = 0; i < command->arg_count; ++i)
    printf("\t\tArg %d: %s\n", i, command->args[i]);
  if (command->next) {
    printf("\tPiped to:\n");
    print_command(command->next);
  }
}

/**
 * Release allocated memory of a command
 * @param  command [description]
 * @return         [description]
 */
int free_command(struct command_t *command) {
  if (command->arg_count) {
    for (int i = 0; i < command->arg_count; ++i)
      free(command->args[i]);
    free(command->args);
  }
  for (int i = 0; i < 3; ++i)
    if (command->redirects[i])
      free(command->redirects[i]);
  if (command->next) {
    free_command(command->next);
    command->next = NULL;
  }
  free(command->name);
  free(command);
  return 0;
}

/**
 * Show the command prompt
 * @return [description]
 */
int show_prompt() {
  char cwd[1024], hostname[1024];
  gethostname(hostname, sizeof(hostname));
  getcwd(cwd, sizeof(cwd));
  printf("%s@%s:%s %s$ ", getenv("USER"), hostname, cwd, sysname);
  return 0;
}

/**
 * Parse a command string into a command struct
 * @param  buf     [description]
 * @param  command [description]
 * @return         0
 */
int parse_command(char *buf, struct command_t *command) {
  const char *splitters = " \t"; // split at whitespace
  int index, len;
  len = strlen(buf);
  while (len > 0 && strchr(splitters, buf[0]) != NULL) // trim left whitespace
  {
    buf++;
    len--;
  }
  while (len > 0 && strchr(splitters, buf[len - 1]) != NULL)
    buf[--len] = 0; // trim right whitespace

  if (len > 0 && buf[len - 1] == '?') // auto-complete
    command->auto_complete = true;
  if (len > 0 && buf[len - 1] == '&') // background
    command->background = true;

  char *pch = strtok(buf, splitters);
  if (pch == NULL) {
    command->name = (char *)malloc(1);
    command->name[0] = 0;
  } else {
    command->name = (char *)malloc(strlen(pch) + 1);
    strcpy(command->name, pch);
  }

  command->args = (char **)malloc(sizeof(char *));

  int redirect_index;
  int arg_index = 0;
  char temp_buf[1024], *arg;
  while (1) {
    // tokenize input on splitters
    pch = strtok(NULL, splitters);
    if (!pch)
      break;
    arg = temp_buf;
    strcpy(arg, pch);
    len = strlen(arg);

    if (len == 0)
      continue; // empty arg, go for next
    while (len > 0 && strchr(splitters, arg[0]) != NULL) // trim left whitespace
    {
      arg++;
      len--;
    }
    while (len > 0 && strchr(splitters, arg[len - 1]) != NULL)
      arg[--len] = 0; // trim right whitespace
    if (len == 0)
      continue; // empty arg, go for next

    // piping to another command
    if (strcmp(arg, "|") == 0) {
      struct command_t *c =
          (struct command_t *)malloc(sizeof(struct command_t));
      int l = strlen(pch);
      pch[l] = splitters[0]; // restore strtok termination
      index = 1;
      while (pch[index] == ' ' || pch[index] == '\t')
        index++; // skip whitespaces

      parse_command(pch + index, c);
      pch[l] = 0; // put back strtok termination
      command->next = c;
      continue;
    }

    // background process
    if (strcmp(arg, "&") == 0)
      continue; // handled before

    // handle input redirection
    redirect_index = -1;
    if (arg[0] == '<')
      redirect_index = 0;
    if (arg[0] == '>') {
      if (len > 1 && arg[1] == '>') {
        redirect_index = 2;
        arg++;
        len--;
      } else
        redirect_index = 1;
    }
    if (redirect_index != -1) {
      command->redirects[redirect_index] = (char *)malloc(len);
      strcpy(command->redirects[redirect_index], arg + 1);
      continue;
    }

    // normal arguments
    if (len > 2 &&
        ((arg[0] == '"' && arg[len - 1] == '"') ||
         (arg[0] == '\'' && arg[len - 1] == '\''))) // quote wrapped arg
    {
      arg[--len] = 0;
      arg++;
    }
    command->args =
        (char **)realloc(command->args, sizeof(char *) * (arg_index + 1));
    command->args[arg_index] = (char *)malloc(len + 1);
    strcpy(command->args[arg_index++], arg);
  }
  command->arg_count = arg_index;

  // increase args size by 2
  command->args = (char **)realloc(command->args,
                                   sizeof(char *) * (command->arg_count += 2));

  // shift everything forward by 1
  for (int i = command->arg_count - 2; i > 0; --i)
    command->args[i] = command->args[i - 1];

  // set args[0] as a copy of name
  command->args[0] = strdup(command->name);
  // set args[arg_count-1] (last) to NULL
  command->args[command->arg_count - 1] = NULL;

  return 0;
}

void prompt_backspace() {
  putchar(8);   // go back 1
  putchar(' '); // write empty over
  putchar(8);   // go back 1 again
}

/**
 * Prompt a command from the user
 * @param  buf      [description]
 * @param  buf_size [description]
 * @return          [description]
 */
int prompt(struct command_t *command) {
  int index = 0;
  char c;
  char buf[4096];
  static char oldbuf[4096];

  // tcgetattr gets the parameters of the current terminal
  // STDIN_FILENO will tell tcgetattr that it should write the settings
  // of stdin to oldt
  static struct termios backup_termios, new_termios;
  tcgetattr(STDIN_FILENO, &backup_termios);
  new_termios = backup_termios;
  // ICANON normally takes care that one line at a time will be processed
  // that means it will return if it sees a "\n" or an EOF or an EOL
  new_termios.c_lflag &=
      ~(ICANON |
        ECHO); // Also disable automatic echo. We manually echo each char.
  // Those new settings will be set to STDIN
  // TCSANOW tells tcsetattr to change attributes immediately.
  tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

  show_prompt();
  buf[0] = 0;
  while (1) {
    c = getchar();
    // printf("Keycode: %u\n", c); // DEBUG: uncomment for debugging

    if (c == 9) // handle tab
    {
      buf[index++] = '?'; // autocomplete
      break;
    }

    if (c == 127) // handle backspace
    {
      if (index > 0) {
        prompt_backspace();
        index--;
      }
      continue;
    }

    if (c == 27 || c == 91 || c == 66 || c == 67 || c == 68) {
      continue;
    }

    if (c == 65) // up arrow
    {
      while (index > 0) {
        prompt_backspace();
        index--;
      }

      char tmpbuf[4096];
      printf("%s", oldbuf);
      strcpy(tmpbuf, buf);
      strcpy(buf, oldbuf);
      strcpy(oldbuf, tmpbuf);
      index += strlen(buf);
      continue;
    }

    putchar(c); // echo the character
    buf[index++] = c;
    if (index >= sizeof(buf) - 1)
      break;
    if (c == '\n') // enter key
      break;
    if (c == 4) // Ctrl+D
      return EXIT;
  }
  if (index > 0 && buf[index - 1] == '\n') // trim newline from the end
    index--;
  buf[index++] = '\0'; // null terminate string

  strcpy(oldbuf, buf);

  parse_command(buf, command);

  // print_command(command); // DEBUG: uncomment for debugging

  // restore the old settings
  tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
  return SUCCESS;
}

//for part1 I used execvp as it is indicated
static char *resolve_in_path(const char *cmd) {
  if (strchr(cmd, '/')) {
    if (access(cmd, X_OK) == 0)
      return strdup(cmd);
    return NULL;
  }
  const char *path_env = getenv("PATH");
  if (!path_env)
    return NULL;
  char *paths = strdup(path_env);
  char *saveptr = NULL;
  char *dir = strtok_r(paths, ":", &saveptr);
  while (dir) {
    char full[1024];
    snprintf(full, sizeof(full), "%s/%s", dir, cmd);
    if (access(full, X_OK) == 0) {
      free(paths);
      return strdup(full);
    }
    dir = strtok_r(NULL, ":", &saveptr);
  }
  free(paths);
  return NULL;
}

//for cleaning child processes
static void cln_background_children(void) {
    while (waitpid(-1, NULL, WNOHANG) > 0) {
    }
}


//for part2 I implemented this for redirections
static int apply_redirections(struct command_t *cmd) {
  char safe_path[2048];
  if (cmd->redirects[0]) {
    snprintf(safe_path, sizeof(safe_path), "%s", cmd->redirects[0]);
    int fd = open(safe_path, O_RDONLY);
    if (fd < 0) { perror(safe_path); return -1; }
    dup2(fd, STDIN_FILENO);
    close(fd);
  }
  if (cmd->redirects[1]) {
    snprintf(safe_path, sizeof(safe_path), "%s", cmd->redirects[1]);
    int fd = open(safe_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) { perror(safe_path); return -1; }
    dup2(fd, STDOUT_FILENO);
    close(fd);
  }
  if (cmd->redirects[2]) {
    snprintf(safe_path, sizeof(safe_path), "%s", cmd->redirects[2]);
    int fd = open(safe_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) { perror(safe_path); return -1; }
    dup2(fd, STDOUT_FILENO);
    close(fd);
  }
  return 0;
}


//for 3b  I implemented this as a builtin chatroom command
static int builtin_chatroom(struct command_t *command) {

  if (command->arg_count < 4) {
    fprintf(stderr, "-%s: chatroom: usage: chatroom <roomname> <username>\n", sysname);
    return 1;
  }
  char *room_name = command->args[1];
  char *user_name = command->args[2];
  char room_path[1024];
  snprintf(room_path, sizeof(room_path), "/tmp/chatroom-%s", room_name);
 
  // I created the room 
  int mkdir_result = mkdir(room_path, 0777);
  if (mkdir_result < 0 && errno != EEXIST) {
    fprintf(stderr, "-%s: chatroom: could not create room folder\n", sysname);
    return 1;
  }
  char user_fifo_path[1024];
  snprintf(user_fifo_path, sizeof(user_fifo_path), "%s/%s", room_path, user_name);
 
 // I created the user's FIFO
  int mkfifo_result = mkfifo(user_fifo_path, 0666);
  if (mkfifo_result < 0 && errno != EEXIST) {
    fprintf(stderr, "-%s: chatroom: could not create user pipe\n", sysname);
    return 1;
  }
 // I open my own FIFO for reading 
  int my_read_fd = open(user_fifo_path, O_RDONLY | O_NONBLOCK);
  if (my_read_fd < 0) {
    fprintf(stderr, "-%s: chatroom: could not open my pipe for reading\n", sysname);
    return 1;
  }
 
 // I also open my own FIFO
  int my_write_fd = open(user_fifo_path, O_WRONLY | O_NONBLOCK);
  if (my_write_fd < 0) {
    close(my_read_fd);
    fprintf(stderr, "-%s: chatroom: could not open my pipe for writing\n", sysname);
    return 1;
  }

  printf("Welcome to %s!\n", room_name);
  fflush(stdout);

  int need_to_show_prompt = 1;

  while (1) {
    if (need_to_show_prompt) {
      printf("[%s] %s > ", room_name, user_name);
      fflush(stdout);
      need_to_show_prompt = 0;
    }
    fd_set read_fds;
    FD_ZERO(&read_fds);
    FD_SET(STDIN_FILENO, &read_fds);
    FD_SET(my_read_fd, &read_fds);

    int max_fd = my_read_fd;
    if (STDIN_FILENO > max_fd) {
      max_fd = STDIN_FILENO;
    }

    int select_result = select(max_fd + 1, &read_fds, NULL, NULL, NULL);
    if (select_result < 0) {
      if (errno == EINTR) continue;
      break;
    }

    // I checked if there are incoming messages in my FIFO
    if (FD_ISSET(my_read_fd, &read_fds)) {
      char incoming_msg[1024];
      while (1) {
        int bytes_read = read(my_read_fd, incoming_msg, sizeof(incoming_msg) - 1);
        if (bytes_read > 0) {
          incoming_msg[bytes_read] = '\0';
          printf("\n%s", incoming_msg);
          fflush(stdout);
          need_to_show_prompt = 1;
        } else {
          break;
        }
      }
    }

    if (FD_ISSET(STDIN_FILENO, &read_fds)) {
      char input_buffer[1024];
      if (fgets(input_buffer, sizeof(input_buffer), stdin) == NULL) break;

      int input_len = strlen(input_buffer);
      if (input_len > 0 && input_buffer[input_len - 1] == '\n') {
        input_buffer[input_len - 1] = '\0';
        input_len--;
      }

      if (strcmp(input_buffer, "exit") == 0) break;

     char formatted_message[2048];
     snprintf(formatted_message, sizeof(formatted_message), "[%s] %s: %s\n", room_name, user_name, input_buffer);
  
     DIR *room_dir = opendir(room_path);
      if (room_dir != NULL) {
        struct dirent *dir_entry;
        while ((dir_entry = readdir(room_dir)) != NULL) {
          if (strcmp(dir_entry->d_name, ".") == 0 || strcmp(dir_entry->d_name, "..") == 0) continue;
          if (strcmp(dir_entry->d_name, user_name) == 0) continue;

          char other_fifo_path[2048];
          snprintf(other_fifo_path, sizeof(other_fifo_path), "%s/%s", room_path, dir_entry->d_name);

          pid_t child_pid = fork();
          if (child_pid == 0) {
            int other_fd = open(other_fifo_path, O_WRONLY | O_NONBLOCK);
            if (other_fd >= 0) {
              write(other_fd, formatted_message, strlen(formatted_message));
              close(other_fd);
            }
            exit(0);
          } else if (child_pid > 0) {
            waitpid(child_pid, NULL, 0);
          }
        }
        closedir(room_dir);
      }
      need_to_show_prompt = 1;
    }
  }

  close(my_write_fd);
  close(my_read_fd);
  return 0;
}


// I implemented this as a builtin bookmark command for part 3c
// it lets user save directory paths with a name and go to them quickly
// bookmarks are stored in ~/.shellish_bookmarks file  and each line in the file has the format: name:path
static int builtin_bookmark(struct command_t *command) {

  // I check if user gave a subcommand
  if (command->arg_count < 3) {
    fprintf(stderr, "-%s: bookmark: usage: bookmark <add|list|go|remove> ...\n", sysname);
    return 1;
  }
  char *subcommand = command->args[1];
  char bookmarks_file[1024];
  char *home_dir = getenv("HOME");
  if (home_dir == NULL) {
    fprintf(stderr, "-%s: bookmark: could not find HOME directory\n", sysname);
    return 1;
  }
  snprintf(bookmarks_file, sizeof(bookmarks_file), "%s/.shellish_bookmarks", home_dir);
  
  // handling list subcommand it reads the bookmarks file and prints all saved bookmarks
  if (strcmp(subcommand, "list") == 0) {
    FILE *file = fopen(bookmarks_file, "r");
    if (file == NULL) {
      printf("no bookmarks saved yet\n");
      return 0;
    }
    char line[2048];
    int count = 1;
    printf("saved bookmarks:\n");
    while (fgets(line, sizeof(line), file) != NULL) {
      int len = strlen(line);
      if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
      }
      printf("  %d. %s\n", count, line);
      count++;
    }
    fclose(file);
    return 0;
  }
 

  // handling add subcommand  it saves a new bookmark with the given name and path
  if (strcmp(subcommand, "add") == 0) {
    if (command->arg_count < 5) {
      fprintf(stderr, "-%s: bookmark: usage: bookmark add <name> <path>\n", sysname);
      return 1;
    }
    char *bookmark_name = command->args[2];
    char *bookmark_path = command->args[3];

    FILE *file = fopen(bookmarks_file, "a");
    if (file == NULL) {
      fprintf(stderr, "-%s: bookmark: could not open bookmarks file\n", sysname);
      return 1;
    }
    fprintf(file, "%s:%s\n", bookmark_name, bookmark_path);
    fclose(file);
    printf("bookmark '%s' saved for path '%s'\n", bookmark_name, bookmark_path);
    return 0;
  }

  // handling go subcommand it finds the bookmark by name and changes directory to its path
  if (strcmp(subcommand, "go") == 0) {
    if (command->arg_count < 4) {
      fprintf(stderr, "-%s: bookmark: usage: bookmark go <name>\n", sysname);
      return 1;
    }
    char *bookmark_name = command->args[2];

    FILE *file = fopen(bookmarks_file, "r");
    if (file == NULL) {
      fprintf(stderr, "-%s: bookmark: no bookmarks saved yet\n", sysname);
      return 1;
    }

    char line[2048];
    int found = 0;
    while (fgets(line, sizeof(line), file) != NULL) {
      int len = strlen(line);
      if (len > 0 && line[len - 1] == '\n') {
        line[len - 1] = '\0';
      }
      char *colon = strchr(line, ':');
      if (colon == NULL) continue;

    
      *colon = '\0';
      char *saved_name = line;
      char *saved_path = colon + 1;

      if (strcmp(saved_name, bookmark_name) == 0) {
        int cd_result = chdir(saved_path);
        if (cd_result < 0) {
          fprintf(stderr, "-%s: bookmark: could not go to '%s': %s\n", sysname, saved_path, strerror(errno));
          fclose(file);
          return 1;
        }
        printf("moved to '%s'\n", saved_path);
        found = 1;
        break;
      }
    }
    fclose(file);

    if (found == 0) {
      fprintf(stderr, "-%s: bookmark: '%s' not found\n", sysname, bookmark_name);
      return 1;
    }
    return 0;
  }

  // handling remove subcommand  it deletes a bookmark by name from the file
  if (strcmp(subcommand, "remove") == 0) {
    if (command->arg_count < 4) {
      fprintf(stderr, "-%s: bookmark: usage: bookmark remove <name>\n", sysname);
      return 1;
    }
    char *bookmark_name = command->args[2];

    FILE *file = fopen(bookmarks_file, "r");
    if (file == NULL) {
      fprintf(stderr, "-%s: bookmark: no bookmarks saved yet\n", sysname);
      return 1;
    }
    char all_lines[100][2048];
    int line_count = 0;
    while (fgets(all_lines[line_count], sizeof(all_lines[line_count]), file) != NULL) {
      line_count++;
    }
    fclose(file);
    FILE *new_file = fopen(bookmarks_file, "w");
    if (new_file == NULL) {
      fprintf(stderr, "-%s: bookmark: could not update bookmarks file\n", sysname);
      return 1;
    }

    int removed = 0;
    for (int i = 0; i < line_count; i++) {
      char line_copy[2048];
      strcpy(line_copy, all_lines[i]);

      int len = strlen(line_copy);
      if (len > 0 && line_copy[len - 1] == '\n') {
        line_copy[len - 1] = '\0';
      }

      char *colon = strchr(line_copy, ':');
      if (colon != NULL) {
        *colon = '\0';
        if (strcmp(line_copy, bookmark_name) == 0) {
          removed = 1;
          continue;
        }
      }
      fprintf(new_file, "%s", all_lines[i]);
    }
    fclose(new_file);

    if (removed == 1) {
      printf("bookmark '%s' removed\n", bookmark_name);
    } else {
      fprintf(stderr, "-%s: bookmark: '%s' not found\n", sysname, bookmark_name);
    }
    return 0;
  }

  fprintf(stderr, "-%s: bookmark: unknown subcommand '%s'\n", sysname, subcommand);
  return 1;
}


//for 3a  I implemented this as a builtin cut command
static int builtin_cut(struct command_t *command) {
  char delimiter_char = '\t';
  int requested_fields[500];
  int number_of_fields = 0;
  int found_f_option = 0;
  int arg_index = 1;
  while (arg_index < command->arg_count - 1) {
    char *current_arg = command->args[arg_index];
    if (current_arg == NULL) {
      break;
    }
    if (strcmp(current_arg, "-d") == 0 || strcmp(current_arg, "--delimiter") == 0) {
      int next_index = arg_index + 1;
      if (next_index < command->arg_count - 1 && command->args[next_index] != NULL) {
        delimiter_char = command->args[next_index][0];
        arg_index += 2; 
        continue;
      }
    }
    if (current_arg[0] == '-' && current_arg[1] == 'd' && current_arg[2] != '\0') {
      delimiter_char = current_arg[2];
      arg_index++;
      continue;
    }
    if (strcmp(current_arg, "-f") == 0 || strcmp(current_arg, "--fields") == 0) {
      int next_index = arg_index + 1;
      if (next_index < command->arg_count - 1 && command->args[next_index] != NULL) {
        char *fields_copy = strdup(command->args[next_index]);
        char *one_field = strtok(fields_copy, ",");
        while (one_field != NULL) {
          int field_num = atoi(one_field);
          if (number_of_fields < 500) {
            requested_fields[number_of_fields] = field_num;
            number_of_fields++;
          }
          one_field = strtok(NULL, ",");
        }
        free(fields_copy);
        found_f_option = 1;
        arg_index += 2;
        continue;
      }
    }
    if (current_arg[0] == '-' && current_arg[1] == 'f' && current_arg[2] != '\0') {
      char *fields_copy = strdup(current_arg + 2);
      char *one_field = strtok(fields_copy, ",");
      while (one_field != NULL) {
        int field_num = atoi(one_field);
        if (number_of_fields < 500) {
          requested_fields[number_of_fields] = field_num;
          number_of_fields++;
        }
        one_field = strtok(NULL, ",");
      }
      free(fields_copy);
      found_f_option = 1;
      arg_index++;
      continue;
    }

    arg_index++;
  }
  if (found_f_option == 0 || number_of_fields == 0) {
    fprintf(stderr, "-%s: cut: need to provide -f with field numbers\n", sysname);
    return 1;
  }
  char line_buffer[4096];

  while (fgets(line_buffer, sizeof(line_buffer), stdin) != NULL) {
    int line_length = strlen(line_buffer);
    if (line_length > 0 && line_buffer[line_length - 1] == '\n') {
      line_buffer[line_length - 1] = '\0';
      line_length--;
    }

  
    char line_copy[4096];
    strcpy(line_copy, line_buffer);
    char *field_pointers[500];
    int total_fields_in_line = 0;
    char delim_string[2];
    delim_string[0] = delimiter_char;
    delim_string[1] = '\0';

    char *current_token = strtok(line_copy, delim_string);
    while (current_token != NULL && total_fields_in_line < 500) {
      field_pointers[total_fields_in_line] = current_token;
      total_fields_in_line++;
      current_token = strtok(NULL, delim_string);
    }

    int fi = 0;
    while (fi < number_of_fields) {
      int array_index = requested_fields[fi] - 1;
      if (array_index >= 0 && array_index < total_fields_in_line) {
        printf("%s", field_pointers[array_index]);
      }
      if (fi < number_of_fields - 1) {
        printf("%c", delimiter_char);
      }

      fi++;
    }
    
    printf("\n");
  }
  return 0;
}

   

//part2 I implemented to run a pipiline recursively
//each call forks the left command and passes pipe read end to the right side
static pid_t exec_pipeline(struct command_t *cmd) {
   if (!cmd->next) {
    char *fullpath = resolve_in_path(cmd->name);
    if (!fullpath) {
      printf("-%s: %s: command not found\n", sysname, cmd->name);
      return -1;
    }
    pid_t pid = fork();
    if (pid == 0) { // child
      if (apply_redirections(cmd) != 0) exit(1);
     
      //chatroom control
      if (strcmp(cmd->name, "chatroom") == 0) {
         free(fullpath);
         exit(builtin_chatroom(cmd));
      }

      if (strcmp(cmd->name, "bookmark") == 0) {
         free(fullpath);
         exit(builtin_bookmark(cmd));
      }

      if (strcmp(cmd->name, "cut") == 0) {
        free(fullpath);
        exit(builtin_cut(cmd));
      }
      execv(fullpath, cmd->args);
      printf("-%s: %s: command not found\n", sysname, cmd->name);
      free(fullpath);
      exit(127);
    }
    free(fullpath);
    return pid;
  }

  int pipefd[2];
  pipe(pipefd);
  char *fullpath = resolve_in_path(cmd->name);
  if (!fullpath) {
    printf("-%s: %s: command not found\n", sysname, cmd->name);
    close(pipefd[0]); close(pipefd[1]);
    return -1;
  }
  pid_t pid_left = fork();
  if (pid_left == 0) {
    close(pipefd[0]);
    dup2(pipefd[1], STDOUT_FILENO);
    close(pipefd[1]);
    if (apply_redirections(cmd) != 0) exit(1);
    execv(fullpath, cmd->args);
    printf("-%s: %s: command not found\n", sysname, cmd->name);
    free(fullpath);
    exit(127);
  }
  free(fullpath);
  close(pipefd[1]); 

  pid_t pid_right = fork();
  if (pid_right == 0) { 
    dup2(pipefd[0], STDIN_FILENO);
    close(pipefd[0]);
    pid_t result = exec_pipeline(cmd->next);
    if (result > 0) waitpid(result, NULL, 0);
    exit(0);
  }
  close(pipefd[0]);
  waitpid(pid_left, NULL, 0);
  return pid_right;
}

int process_command(struct command_t *command) {
  int r;
  if (strcmp(command->name, "") == 0)
    return SUCCESS;

  if (strcmp(command->name, "exit") == 0)
    return EXIT;

  if (strcmp(command->name, "cd") == 0) {
    if (command->arg_count > 0) {
      r = chdir(command->args[1]);
      if (r == -1)
        printf("-%s: %s: %s\n", sysname, command->name, strerror(errno));
      return SUCCESS;
    }
  }

  if (strcmp(command->name, "chatroom") == 0) {
     exit(builtin_chatroom(command));
  }
 
  if (strcmp(command->name, "bookmark") == 0) {
      return builtin_bookmark(command);
  }

  pid_t pid = fork();
  // I added fork error check
  if (pid < 0) {
    perror("fork");
    return SUCCESS;
  }
  if (pid == 0) // child
  {
    /// This shows how to do exec with environ (but is not available on MacOs)
    // extern char** environ; // environment variables
    // execvpe(command->name, command->args, environ); // exec+args+path+environ

    /// This shows how to do exec with auto-path resolve
    // add a NULL argument to the end of args, and the name to the beginning
    // as required by exec

    // TODO: do your own exec with path resolving using execv()
    // do so by replacing the execvp call below
    // execvp(command->name, command->args); // exec+args+path
    // printf("-%s: %s: command not found\n", sysname, command->name);
    // exit(127);

    
    if (command->next) {
      pid_t pipe_pid = exec_pipeline(command);
      if (pipe_pid > 0) waitpid(pipe_pid, NULL, 0);
      exit(0);
    }
    if (strcmp(command->name, "cut") == 0) {
      exit(builtin_cut(command));
    }
    // I added path resolving with execv 
    char *fullpath = resolve_in_path(command->name);
    if (!fullpath) {
      printf("-%s: %s: command not found\n", sysname, command->name);
      exit(127);
    }
    if (apply_redirections(command) != 0) { free(fullpath); exit(1); }
    execv(fullpath, command->args);
    printf("-%s: %s: command not found\n", sysname, command->name);
    free(fullpath);
    exit(127);
  } else {
    // TODO: implement background processes here
    // wait(0); // wait for child process to finish

    // I added reap background children and background support
    cln_background_children();
    if (command->background)
      return SUCCESS;
    waitpid(pid, NULL, 0);
    return SUCCESS;
  }
}

int main() {
  while (1) {
    struct command_t *command =
        (struct command_t *)malloc(sizeof(struct command_t));
    memset(command, 0, sizeof(struct command_t)); // set all bytes to 0

    int code;
    code = prompt(command);
    if (code == EXIT)
      break;

    code = process_command(command);
    if (code == EXIT)
      break;

    free_command(command);
  }

  printf("\n");
  return 0;
}
