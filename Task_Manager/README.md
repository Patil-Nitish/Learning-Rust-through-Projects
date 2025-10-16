# Task Manager

A simple, interactive command-line task management application built with Rust for organizing and tracking your tasks.

## Overview

Task Manager is a lightweight CLI application that helps you manage your daily tasks. It provides a straightforward interface for adding, viewing, and removing tasks, all from the comfort of your terminal.

## Features

- **Add Tasks**: Quickly add task descriptions
- **View Tasks**: Display all your current tasks in a numbered list
- **Remove Tasks**: Delete completed or unwanted tasks by number
- **Interactive Menu**: User-friendly menu-driven interface
- **In-Memory Storage**: Tasks are stored during the session

## Prerequisites

- Rust 1.70 or higher
- Cargo

## Installation

Navigate to the Task_Manager directory:

```bash
cd Task_Manager
```

Build the project:

```bash
cargo build --release
```

## Usage

Run the application:

```bash
cargo run
```

Or use the compiled binary:

```bash
./target/release/Task_Manager
```

## Menu Options

The Task Manager presents a simple menu with four options:

### 1. Add Task
Add a new task to your list:
```
Enter task description: Complete Rust project
```

### 2. View Tasks
Display all your current tasks:
```
Tasks:
1. Complete Rust project
2. Review pull requests
3. Update documentation
```

### 3. Remove Task
Remove a task by entering its number:
```
Enter task number to remove: 2
Task removed successfully.
```

### 4. Exit
Exit the Task Manager application.

## Example Session

```
===== Task Manager =====
===== 1. Add Task =====
===== 2. View Tasks =====
===== 3. Remove Task =====
===== 4. Exit =====
===========================
Please enter your choice(1-4):
1

Enter task description:
Write README for Task Manager

===== Task Manager =====
===== 1. Add Task =====
===== 2. View Tasks =====
===== 3. Remove Task =====
===== 4. Exit =====
===========================
Please enter your choice(1-4):
2

Tasks:
1. Write README for Task Manager

===== Task Manager =====
===== 1. Add Task =====
===== 2. View Tasks =====
===== 3. Remove Task =====
===== 4. Exit =====
===========================
Please enter your choice(1-4):
4

Exiting Task Manager
```

## Project Structure

```
Task_Manager/
├── src/
│   └── main.rs      # Main application logic
├── Cargo.toml       # Project configuration
└── README.md        # This file
```

## Technical Details

- **Language**: Rust
- **Storage**: In-memory vector (`Vec<String>`)
- **Input/Output**: Standard I/O (`std::io`)
- **User Interface**: Terminal-based menu system

## Limitations

- Tasks are not persisted to disk (lost when application closes)
- No task prioritization or categorization
- No due dates or reminders
- Single-user, single-session only

## Future Enhancements

Potential features for future versions:
- [ ] Persistent storage (save to file)
- [ ] Task priorities and categories
- [ ] Due dates and deadlines
- [ ] Task search and filter
- [ ] Mark tasks as complete (instead of removing)
- [ ] Export tasks to various formats

## Error Handling

The application handles common errors:
- Empty input when selecting menu options
- Invalid task numbers when removing tasks
- Invalid menu choices

## Learning Outcomes

This project demonstrates:
- Basic Rust syntax and control flow
- Working with vectors and strings
- User input handling
- Match expressions and pattern matching
- Loop control and program flow

## License

This project is part of the Learning Rust through Projects repository.

## Contributing

Contributions are welcome! Ideas for improvements:
- Add file persistence (JSON, CSV, or database)
- Implement task editing functionality
- Add task completion tracking
- Create a configuration system
