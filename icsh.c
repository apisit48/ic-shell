/* ICCS227: Project 1: icsh
 * Name: Apisit Bawornsutthimontri
 * StudentID: 6180622
 */

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<sys/types.h>
#include<sys/wait.h>
#include<signal.h>
#include<termios.h>
#include<fcntl.h>

#define MAX_CMD_BUFFER 255

pid_t current_pid = -1;
int last_exit_status = 0;


typedef struct Job {
    pid_t pid;
    int jobid;
    char command[MAX_CMD_BUFFER];
    struct Job *next;
} Job;

Job *jobs = NULL;  
int job_count = 0;
int max_jobid = 0;

Job* addJob(pid_t pid, char *command) {
    Job *newJob = (Job*)malloc(sizeof(Job));
    newJob->pid = pid;
    newJob->jobid = ++max_jobid;
    strcpy(newJob->command, command);
    newJob->next = jobs;
    jobs = newJob;
    return newJob;
}

void removeJob(pid_t pid) {
    Job *current = jobs, *prev = NULL;
    while (current != NULL) {
        if (current->pid == pid) {
            if (prev != NULL) {
                prev->next = current->next;
            } else {
                jobs = current->next;
            }
            free(current);
            return;
        }
        prev = current;
        current = current->next;
    }
}

void listJobs() {
    for (Job *current = jobs; current != NULL; current = current->next) {
        printf("[%d]  Running                 %s &\n", current->jobid, current->command);
    }
}

void handle_sigint(int sig) {
    if (current_pid != -1) {
        kill(current_pid, SIGINT);
    }
}

void handle_sigtstp(int sig) {
    if (current_pid != -1) {
        kill(current_pid, SIGTSTP);
    }
}

void executeExternalCommand(char *command, char *args){

    char *argv[MAX_CMD_BUFFER];
    int count = 0;
    argv[count++] = command;
    char *inputFile = NULL;
    char *outputFile = NULL;
    int background = 0;


    if(args) {
        char *token = strtok(args, " ");
        while (token && count < MAX_CMD_BUFFER - 2) {
            if (strcmp(token, "<") == 0) {
                token = strtok(NULL, " ");
                inputFile = token;
            } else if (strcmp(token, ">") == 0) {
                token = strtok(NULL, " ");
                outputFile = token;
            } else if (strcmp(token, "&") == 0) {
                background = 1; 
            } else {
                argv[count++] = token;
            }
            token = strtok(NULL, " ");
        }
    }


    argv[count] = NULL;  
    pid_t pid = fork();


    if (pid == -1) {
        perror("Failed to fork");
        exit(EXIT_FAILURE);
    } 
    
    else if (pid == 0) {

        if (inputFile) {
            int in = open(inputFile, O_RDONLY);
            if (in == -1) {
                perror("Failed to open input file");
                exit(EXIT_FAILURE);
            }
            dup2(in, 0);
            close(in);
        }

        if (outputFile) {
            int out = open(outputFile, O_WRONLY | O_CREAT | O_TRUNC, 0666);
            if (out == -1) {
                perror("Failed to open output file");
                exit(EXIT_FAILURE);
            }
            dup2(out, 1);
            close(out);
        }
        
        execvp(command, argv);
        perror("Failed to execute command");
        exit(EXIT_FAILURE);
    } 
    
    else {
        if (background) {
            char full_command[MAX_CMD_BUFFER];
            snprintf(full_command, sizeof(full_command), "%s %s", command, args ? args : "");
            Job *job = addJob(pid, full_command);
            printf("[%d] %d\n", job->jobid, pid);
            return;
        }
        else {
            current_pid = pid;
            int status;
            waitpid(pid, &status, 0);
            if (WIFEXITED(status)) {
                last_exit_status = WEXITSTATUS(status);
            }
            current_pid = -1;
        }
    }  
}

void commandCheck(char *command, char *oldCommand){

    char copyCommand[MAX_CMD_BUFFER];
    strcpy(copyCommand, command);
    
    char *current = strtok(copyCommand, " ");
    if (!current) return;  
    
    char *args = strtok(NULL, "");
    
    if (strcmp(current, "echo") == 0) {
        if (args && strcmp(args, "$?") == 0) {
            printf("%d\n", last_exit_status);
        } 
        
        else if (args) {  
            printf("%s\n", args);
        }
    }

    else if (strcmp(current, "!!") == 0) {
        if (strlen(oldCommand) > 0) {
            printf("%s\n", oldCommand);
            commandCheck(oldCommand, oldCommand);
        }
    }

    else if (strcmp(current, "exit") == 0)
    {
        int code = 0;
        if (args != NULL)
        {
            code = atoi(args);
            if (code < 0 || code > 255)
            {
                code = code %256;
            }
            
        }
        
        printf("Bye\n");
        exit(code);
    }

    else if (strcmp(current, "jobs") == 0) {
        listJobs();
    } 
    
    else {
        printf("Executing external command\n");
        executeExternalCommand(current, args);
    }    
}

void fileCheck(char *filename){

    FILE *scriptFile = fopen(filename, "r");
    if (!scriptFile) {
        perror("Failed to open the script file");
        exit(1);
    }
    char command[MAX_CMD_BUFFER];
    char oldCommand[MAX_CMD_BUFFER] = {0};

    while (fgets(command, sizeof(command), scriptFile)) {
        size_t len = strlen(command);
        if (len > 0 && command[len-1] == '\n') {
            command[len-1] = '\0';
        }

        commandCheck(command, oldCommand);
        strcpy(oldCommand, command);
    }

    fclose(scriptFile);   
}



void icshell(){

    char command[MAX_CMD_BUFFER];
    char oldCommand[MAX_CMD_BUFFER] = {0};
    while (1)
    {
        pid_t pid;
        int status;
        while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
            removeJob(pid);
            printf("\n[%d]+  Done\n", max_jobid); // assuming jobid is associated with process
            printf("icsh $ ");
        }

        printf("icsh $ ");
        fgets(command, 255, stdin);
        
        size_t len = strlen(command);
        if (len > 0 && command[len-1] == '\n') {
            command[len-1] = '\0';
        }

        if (command[0] == '\n' || command[0] == '\0') {
            continue;  
        }   
        commandCheck(command,oldCommand);
        strcpy(oldCommand, command);
    }
    
}



int main(int argc, char *argv[]) {

    signal(SIGINT, handle_sigint);
    signal(SIGTSTP, handle_sigtstp);
    if (argc > 1) {
        fileCheck(argv[1]);
    } 
    
    else {
        printf("Starting IC shell\n");
        icshell();
    }
    return 0;
}
