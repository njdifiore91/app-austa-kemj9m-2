import cluster from 'cluster';
import os from 'os';
import app from './index';

const numCPUs = os.cpus().length;

if (cluster.isPrimary) {
    console.log(`Primary ${process.pid} is running`);

    // Fork workers based on CPU cores
    for (let i = 0; i < numCPUs; i++) {
        cluster.fork();
    }

    cluster.on('exit', (worker, code, signal) => {
        console.log(`Worker ${worker.process.pid} died`);
        // Replace the dead worker
        cluster.fork();
    });
} else {
    // Workers can share any TCP connection
    const port = process.env.PORT || 4000;
    
    app.listen(port, () => {
        console.log(`Worker ${process.pid} started and listening on port ${port}`);
    });
} 