use std::sync::{mpsc, Arc, Mutex};

struct ThreadPool {

}

type Job = Box<dyn FnOnce() + Send + 'static>;

impl ThreadPool {
    pub fn new(size:usize)  {
        assert!(size > 0);

        // let (sender, receiver) = mpsc::channel();

        // let receiver = Arc::new(Mutex::new(receiver));


    }

    pub fn execute<F>(&self,f:F)
    where F: FnOnce() + Send + 'static, {

    }
}