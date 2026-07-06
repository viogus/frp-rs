fn main() {
    let num_cores = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4);
    
    let worker_threads = (num_cores * 2).max(4);
    
    println!("CPU 核心数: {}", num_cores);
    println!("配置的工作线程数: {}", worker_threads);
    println!("阻塞线程池大小: 512");
}
