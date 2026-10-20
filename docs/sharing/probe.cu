// probe: the small CUDA programs the sharing spike (behavioralstate/spec#65) runs in containers on one card.
//   probe alloc <step MiB> <max MiB> <hold s>   allocate and touch memory in steps until it fails or reaches max, then hold it
//   probe burn <seconds>                        run a compute kernel back to back; print launches per second
//   probe fault                                 write through a bad pointer in a kernel; print the error
//   probe info                                  free and total memory as this process sees them
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <thread>
#include <vector>
#include <cuda_runtime.h>

static double now() {
    return std::chrono::duration<double>(std::chrono::steady_clock::now().time_since_epoch()).count();
}

__global__ void spin(float *out, int n) {
    float a = threadIdx.x * 0.001f, b = 1.0001f;
    for (int i = 0; i < n; i++) a = a * b + 0.0001f;
    out[blockIdx.x * blockDim.x + threadIdx.x] = a;
}

__global__ void bad(int *p) { p[threadIdx.x] = 42; }

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: probe alloc|burn|fault|info ...\n"); return 2; }
    size_t free_b = 0, total_b = 0;
    cudaError_t e = cudaMemGetInfo(&free_b, &total_b);
    if (e != cudaSuccess) { printf("init failed: %s\n", cudaGetErrorString(e)); return 1; }
    printf("seen: free %zu MiB of %zu MiB\n", free_b >> 20, total_b >> 20);
    fflush(stdout);
    if (!strcmp(argv[1], "info")) return 0;
    if (!strcmp(argv[1], "alloc")) {
        size_t step = (size_t)atoi(argv[2]) << 20, max = (size_t)atoi(argv[3]) << 20;
        int hold = atoi(argv[4]);
        std::vector<void *> held;
        size_t got = 0;
        while (got < max) {
            void *p = nullptr;
            e = cudaMalloc(&p, step);
            if (e == cudaSuccess) e = cudaMemset(p, 1, step);
            if (e == cudaSuccess) e = cudaDeviceSynchronize();
            if (e != cudaSuccess) { printf("alloc failed at %zu MiB: %s\n", got >> 20, cudaGetErrorString(e)); fflush(stdout); break; }
            held.push_back(p);
            got += step;
        }
        printf("holding %zu MiB for %d s\n", got >> 20, hold);
        fflush(stdout);
        std::this_thread::sleep_for(std::chrono::seconds(hold));
        printf("alloc done\n");
        return e == cudaSuccess ? 0 : 3;
    }
    if (!strcmp(argv[1], "burn")) {
        double seconds = atof(argv[2]);
        int blocks = 4096, threads = 256;
        float *out;
        cudaMalloc(&out, sizeof(float) * blocks * threads);
        spin<<<blocks, threads>>>(out, 2000);
        cudaDeviceSynchronize();
        double t0 = now(), last = t0;
        long launches = 0;
        while (now() - t0 < seconds) {
            spin<<<blocks, threads>>>(out, 2000);
            e = cudaDeviceSynchronize();
            if (e != cudaSuccess) { printf("burn failed after %ld launches: %s\n", launches, cudaGetErrorString(e)); return 4; }
            launches++;
            if (now() - last >= 5) { printf("  %.0f s: %.1f launches/s\n", now() - t0, launches / (now() - t0)); fflush(stdout); last = now(); }
        }
        printf("burn: %ld launches in %.1f s = %.2f launches/s\n", launches, now() - t0, launches / (now() - t0));
        return 0;
    }
    if (!strcmp(argv[1], "fault")) {
        bad<<<1, 32>>>((int *)0x10);
        e = cudaDeviceSynchronize();
        printf("fault: %s\n", cudaGetErrorString(e));
        return 5;
    }
    fprintf(stderr, "unknown %s\n", argv[1]);
    return 2;
}
