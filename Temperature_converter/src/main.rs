fn cel_to_far(c: f64) -> f64 {
    (c*9.0/5.0)+32.0
}

fn far_to_cel(f:f64)->f64{
    (f-32.0)*5.0/9.0
}

fn main(){
    let temp_c=25.0;
    let temp_f=77.0;

    let f=cel_to_far(temp_c);
    let c=far_to_cel(temp_f);

    println!("{temp_c} C is {f} F");
    println!("{temp_f} F is {c} C");

}