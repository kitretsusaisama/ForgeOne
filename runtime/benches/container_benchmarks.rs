use criterion::{black_box, criterion_group, criterion_main, Criterion};
use runtime::config::ContainerConfig;

// Benchmark for container configuration creation
fn bench_container_config(c: &mut Criterion) {
    c.bench_function("create container config", |b| {
        b.iter(|| {
            let config = ContainerConfig::builder()
                .image(black_box("my-image:latest"))
                .name(black_box("benchmark-container"))
                .command(black_box("/bin/sh"))
                .args(black_box(vec!["-c", "echo hello"]))
                .build();
            black_box(config)
        })
    });
}

// Benchmark for container configuration validation
fn bench_validate_config(c: &mut Criterion) {
    let config = ContainerConfig::builder()
        .image("my-image:latest")
        .name("benchmark-container")
        .command("/bin/sh")
        .args(vec!["-c", "echo hello"])
        .build();

    c.bench_function("validate container config", |b| {
        b.iter(|| {
            let result = runtime::config::validate_config(black_box(&config));
            black_box(result)
        })
    });
}

// Benchmark for container creation
fn bench_create_container(c: &mut Criterion) {
    let config = ContainerConfig::builder()
        .image("my-image:latest")
        .name("benchmark-container")
        .command("/bin/sh")
        .args(vec!["-c", "echo hello"])
        .build();

    c.bench_function("create container", |b| {
        b.iter(|| {
            // Note: In a real benchmark, you might want to mock this
            // or use a test container image to avoid actual container creation
            let result = runtime::registry::create_container(
                black_box("my-image:latest"),
                black_box(None),
                black_box(Some(&config)),
            );
            black_box(result)
        })
    });
}

criterion_group!(
    benches,
    bench_container_config,
    bench_validate_config,
    bench_create_container
);
criterion_main!(benches);
