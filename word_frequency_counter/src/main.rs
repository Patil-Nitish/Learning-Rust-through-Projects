use std::io;



fn main() {
let mut input=String::new();
println!("Enter a sentence:");
io::stdin().read_line(&mut input).expect("failed to read line");

let input =input
.to_lowercase()
.replace(['.',',','!','?',':',':']," ");


let words: Vec<&str>=input.split_whitespace().collect();

let mut freq_list:Vec<(String,usize)>=Vec::new();

for w in words{
    let mut found=false;

    for pair in &mut freq_list{
        if pair.0==w{
            pair.1+=1;
            found=true;
            break;
        }
        
        }
        if !found{
            freq_list.push((w.to_string(),1));
    }

}

println!("Word Frequency List:");
for (word,count) in &freq_list{
    println!("{}: {}",word, count);
}
}
