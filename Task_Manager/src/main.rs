use std::io;

fn main() {
    let mut tasks: Vec<String> = Vec::new();

    loop {
        println!();
        println!("===== Task Manager =====");
        println!("===== 1. Add Task =====");
        println!("===== 2. View Tasks =====");
        println!("===== 3. Remove Task =====");
        println!("===== 4. Exit =====");
        println!("===========================");
        println!("Please enter your choice(1-4):");
        let mut choice = String::new();
        io::stdin().read_line(&mut choice).expect("Failed to read choice");
        let choice = choice.trim();

        if choice.is_empty() {
            println!("No choice entered. Please try again.");
            continue;
        }

        match choice {
            "1" => {
                println!("Enter task decription:");
                let mut task = String::new();
                io::stdin().read_line(&mut task).expect("Failed to read Task");
                tasks.push(task.trim().to_string());
            }
            "2" => {
                if tasks.is_empty() {
                    println!("No tasks available.");
                } else {
                    println!("Tasks:");
                    for (i, task) in tasks.iter().enumerate() {
                        println!("{}. {}", i + 1, task);
                    }
                }
            }
            "3" => {
                if tasks.is_empty() {
                    println!("All task are Completed.");
                } else {
                    println!("Enter task number to remove:");
                    let mut task_num = String::new();
                    io::stdin().read_line(&mut task_num).expect("Failed to read task number");

                    match task_num.trim().parse::<usize>() {
                        Ok(num) if num > 0 && num <= tasks.len() => {
                            tasks.remove(num - 1);
                            println!("Task removed successfully.");
                        }
                       _ =>println!("Invalid task number."),
                       
                    }
                }
            }
            "4"=>{
                println!("Exiting Task Manager");
                break;
            }
            _=>{
                println!("Invalid choice. Please enter a number between 1 and 4.");
            }
        }
    }
}
