use criterion::{black_box, criterion_group, criterion_main, Criterion};
use runtime::config::ContainerConfig;

// Benchmark for container configuration creation
fn bench_container_config(c: &mut Criterion) {
    c.bench_function("create container config", |b| {
        b.iter(|| {
            let mut config = ContainerConfig::new(black_box("my-image:latest"));
            config.name = Some(black_box("benchmark-container").to_string());
            config.command = Some(black_box("/bin/sh").to_string());
            config.args = Some(black_box(vec!["-c".to_string(), "echo hello".to_string()]));
            black_box(config)
        })
    });
}

// Benchmark for container configuration validation
fn bench_validate_config(c: &mut Criterion) {
    let mut config = ContainerConfig::new("my-image:latest");
    config.name = Some("benchmark-container".to_string());
    config.command = Some("/bin/sh".to_string());
    config.args = Some(vec!["-c".to_string(), "echo hello".to_string()]);

    c.bench_function("validate container config", |b| {
        b.iter(|| {
            let result = runtime::config::validate_config(black_box(&config));
            black_box(result)
        })
    });
}

// Benchmark for container creation
fn bench_create_container(c: &mut Criterion) {
    let mut config = ContainerConfig::new("my-image:latest");
    config.name = Some("benchmark-container".to_string());
    config.command = Some("/bin/sh".to_string());
    config.args = Some(vec!["-c".to_string(), "echo hello".to_string()]);

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
