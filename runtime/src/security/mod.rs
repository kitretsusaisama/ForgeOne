//! # Container Security Module
//!
//! This module provides functionality for container security, including isolation,
//! permissions, capabilities, and secure communication. It implements a comprehensive
//! security model for containers with fine-grained access controls, capability management,
//! and secure communication channels.

use common::error::{ForgeError, Result};
use common::observer::trace::ExecutionSpan;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

/// Security isolation level
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationLevel {
    /// Process isolation (minimal)
    Process,
    /// Container isolation (standard)
    Container,
    /// VM isolation (strong)
    VM,
    /// Hardware isolation (strongest)
    Hardware,
    /// Custom isolation
    Custom,
}

impl std::fmt::Display for IsolationLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IsolationLevel::Process => write!(f, "process"),
            IsolationLevel::Container => write!(f, "container"),
            IsolationLevel::VM => write!(f, "vm"),
            IsolationLevel::Hardware => write!(f, "hardware"),
            IsolationLevel::Custom => write!(f, "custom"),
        }
    }
}

/// Security capability
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Capability {
    // System capabilities
    /// Bypass file permission checks
    CHOWN,
    /// Make arbitrary changes to file UIDs and GIDs
    DAC_OVERRIDE,
    /// Bypass file read permission checks
    DAC_READ_SEARCH,
    /// Bypass permission checks on operations that normally require the file system UID of the process to match the UID of the file
    FOWNER,
    /// Don't clear set-user-ID and set-group-ID mode bits when a file is modified
    FSETID,
    /// Bypass permission checks for operations on trusted and security extended attributes
    MAC_ADMIN,
    /// Override Mandatory Access Control (MAC)
    MAC_OVERRIDE,
    /// Allow modification of mount namespace
    SYS_ADMIN,
    /// Allow use of reboot()
    SYS_BOOT,
    /// Allow use of chroot()
    SYS_CHROOT,
    /// Allow system time manipulation
    SYS_TIME,
    /// Allow configuration of the kernel's syslog
    SYSLOG,
    /// Allow manipulation of system memory
    SYS_MODULE,
    /// Allow sending of signals to processes belonging to others
    KILL,
    /// Allow binding to ports below 1024
    NET_BIND_SERVICE,
    /// Allow interface configuration
    NET_ADMIN,
    /// Allow raw network access
    NET_RAW,
    /// Allow use of RAW and PACKET sockets
    NET_BROADCAST,
    /// Allow locking of shared memory segments
    IPC_LOCK,
    /// Override IPC ownership checks
    IPC_OWNER,
    /// Insert and remove kernel modules
    SYS_MODULE,
    /// Perform I/O port operations
    SYS_RAWIO,
    /// Perform operations on trusted and security Extended Attributes
    SECURITY,
    /// Trace arbitrary processes
    SYS_PTRACE,
    /// Set user ID, group ID, and supplementary group IDs
    SETUID,
    /// Set process capabilities
    SETPCAP,
    /// Set file capabilities
    SETFCAP,
    /// Set process resource limits
    SETRLIMIT,
    /// Custom capability
    CUSTOM(u32),
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Capability::CHOWN => write!(f, "CHOWN"),
            Capability::DAC_OVERRIDE => write!(f, "DAC_OVERRIDE"),
            Capability::DAC_READ_SEARCH => write!(f, "DAC_READ_SEARCH"),
            Capability::FOWNER => write!(f, "FOWNER"),
            Capability::FSETID => write!(f, "FSETID"),
            Capability::MAC_ADMIN => write!(f, "MAC_ADMIN"),
            Capability::MAC_OVERRIDE => write!(f, "MAC_OVERRIDE"),
            Capability::SYS_ADMIN => write!(f, "SYS_ADMIN"),
            Capability::SYS_BOOT => write!(f, "SYS_BOOT"),
            Capability::SYS_CHROOT => write!(f, "SYS_CHROOT"),
            Capability::SYS_TIME => write!(f, "SYS_TIME"),
            Capability::SYSLOG => write!(f, "SYSLOG"),
            Capability::SYS_MODULE => write!(f, "SYS_MODULE"),
            Capability::KILL => write!(f, "KILL"),
            Capability::NET_BIND_SERVICE => write!(f, "NET_BIND_SERVICE"),
            Capability::NET_ADMIN => write!(f, "NET_ADMIN"),
            Capability::NET_RAW => write!(f, "NET_RAW"),
            Capability::NET_BROADCAST => write!(f, "NET_BROADCAST"),
            Capability::IPC_LOCK => write!(f, "IPC_LOCK"),
            Capability::IPC_OWNER => write!(f, "IPC_OWNER"),
            Capability::SYS_RAWIO => write!(f, "SYS_RAWIO"),
            Capability::SECURITY => write!(f, "SECURITY"),
            Capability::SYS_PTRACE => write!(f, "SYS_PTRACE"),
            Capability::SETUID => write!(f, "SETUID"),
            Capability::SETPCAP => write!(f, "SETPCAP"),
            Capability::SETFCAP => write!(f, "SETFCAP"),
            Capability::SETRLIMIT => write!(f, "SETRLIMIT"),
            Capability::CUSTOM(id) => write!(f, "CUSTOM({})", id),
        }
    }
}

/// Security profile type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityProfileType {
    /// Privileged profile (all capabilities)
    Privileged,
    /// Restricted profile (limited capabilities)
    Restricted,
    /// Unprivileged profile (minimal capabilities)
    Unprivileged,
    /// Custom profile
    Custom,
}

impl std::fmt::Display for SecurityProfileType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecurityProfileType::Privileged => write!(f, "privileged"),
            SecurityProfileType::Restricted => write!(f, "restricted"),
            SecurityProfileType::Unprivileged => write!(f, "unprivileged"),
            SecurityProfileType::Custom => write!(f, "custom"),
        }
    }
}

/// Security profile
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityProfile {
    /// Profile ID
    pub id: String,
    /// Profile name
    pub name: String,
    /// Profile type
    pub profile_type: SecurityProfileType,
    /// Isolation level
    pub isolation_level: IsolationLevel,
    /// Allowed capabilities
    pub capabilities: HashSet<Capability>,
    /// Allowed syscalls
    pub syscalls: HashSet<String>,
    /// Allowed devices
    pub devices: HashSet<String>,
    /// Allowed mounts
    pub mounts: HashSet<String>,
    /// Allowed networks
    pub networks: HashSet<String>,
    /// No new privileges flag
    pub no_new_privileges: bool,
    /// Read-only root filesystem
    pub read_only_root_fs: bool,
    /// Run as non-root
    pub run_as_non_root: bool,
    /// Allowed UIDs
    pub allowed_uids: HashSet<u32>,
    /// Allowed GIDs
    pub allowed_gids: HashSet<u32>,
    /// SELinux context
    pub selinux_context: Option<String>,
    /// AppArmor profile
    pub apparmor_profile: Option<String>,
    /// Seccomp profile
    pub seccomp_profile: Option<String>,
    /// Custom security options
    pub custom: HashMap<String, String>,
}

impl SecurityProfile {
    /// Create a new security profile
    pub fn new(name: &str, profile_type: SecurityProfileType) -> Self {
        let mut profile = Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            profile_type,
            isolation_level: IsolationLevel::Container,
            capabilities: HashSet::new(),
            syscalls: HashSet::new(),
            devices: HashSet::new(),
            mounts: HashSet::new(),
            networks: HashSet::new(),
            no_new_privileges: true,
            read_only_root_fs: false,
            run_as_non_root: true,
            allowed_uids: HashSet::new(),
            allowed_gids: HashSet::new(),
            selinux_context: None,
            apparmor_profile: None,
            seccomp_profile: None,
            custom: HashMap::new(),
        };

        // Set default capabilities based on profile type
        match profile_type {
            SecurityProfileType::Privileged => {
                // Add all capabilities
                profile.capabilities.insert(Capability::CHOWN);
                profile.capabilities.insert(Capability::DAC_OVERRIDE);
                profile.capabilities.insert(Capability::DAC_READ_SEARCH);
                profile.capabilities.insert(Capability::FOWNER);
                profile.capabilities.insert(Capability::FSETID);
                profile.capabilities.insert(Capability::MAC_ADMIN);
                profile.capabilities.insert(Capability::MAC_OVERRIDE);
                profile.capabilities.insert(Capability::SYS_ADMIN);
                profile.capabilities.insert(Capability::SYS_BOOT);
                profile.capabilities.insert(Capability::SYS_CHROOT);
                profile.capabilities.insert(Capability::SYS_TIME);
                profile.capabilities.insert(Capability::SYSLOG);
                profile.capabilities.insert(Capability::SYS_MODULE);
                profile.capabilities.insert(Capability::KILL);
                profile.capabilities.insert(Capability::NET_BIND_SERVICE);
                profile.capabilities.insert(Capability::NET_ADMIN);
                profile.capabilities.insert(Capability::NET_RAW);
                profile.capabilities.insert(Capability::NET_BROADCAST);
                profile.capabilities.insert(Capability::IPC_LOCK);
                profile.capabilities.insert(Capability::IPC_OWNER);
                profile.capabilities.insert(Capability::SYS_RAWIO);
                profile.capabilities.insert(Capability::SECURITY);
                profile.capabilities.insert(Capability::SYS_PTRACE);
                profile.capabilities.insert(Capability::SETUID);
                profile.capabilities.insert(Capability::SETPCAP);
                profile.capabilities.insert(Capability::SETFCAP);
                profile.capabilities.insert(Capability::SETRLIMIT);

                profile.no_new_privileges = false;
                profile.read_only_root_fs = false;
                profile.run_as_non_root = false;
                profile.isolation_level = IsolationLevel::Process;
            }
            SecurityProfileType::Restricted => {
                // Add limited capabilities
                profile.capabilities.insert(Capability::CHOWN);
                profile.capabilities.insert(Capability::DAC_OVERRIDE);
                profile.capabilities.insert(Capability::FOWNER);
                profile.capabilities.insert(Capability::FSETID);
                profile.capabilities.insert(Capability::NET_BIND_SERVICE);
                profile.capabilities.insert(Capability::SETUID);
                profile.capabilities.insert(Capability::SETGID);

                profile.no_new_privileges = true;
                profile.read_only_root_fs = false;
                profile.run_as_non_root = false;
                profile.isolation_level = IsolationLevel::Container;
            }
            SecurityProfileType::Unprivileged => {
                // Add minimal capabilities
                profile.capabilities.insert(Capability::NET_BIND_SERVICE);

                profile.no_new_privileges = true;
                profile.read_only_root_fs = true;
                profile.run_as_non_root = true;
                profile.isolation_level = IsolationLevel::Container;
            }
            SecurityProfileType::Custom => {
                // No default capabilities
                profile.no_new_privileges = true;
                profile.read_only_root_fs = false;
                profile.run_as_non_root = true;
                profile.isolation_level = IsolationLevel::Container;
            }
        }

        profile
    }

    /// Add a capability
    pub fn add_capability(&mut self, capability: Capability) -> Result<()> {
        self.capabilities.insert(capability);
        Ok(())
    }

    /// Remove a capability
    pub fn remove_capability(&mut self, capability: &Capability) -> Result<()> {
        self.capabilities.remove(capability);
        Ok(())
    }

    /// Check if a capability is allowed
    pub fn has_capability(&self, capability: &Capability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Add a syscall
    pub fn add_syscall(&mut self, syscall: &str) -> Result<()> {
        self.syscalls.insert(syscall.to_string());
        Ok(())
    }

    /// Remove a syscall
    pub fn remove_syscall(&mut self, syscall: &str) -> Result<()> {
        self.syscalls.remove(syscall);
        Ok(())
    }

    /// Check if a syscall is allowed
    pub fn has_syscall(&self, syscall: &str) -> bool {
        self.syscalls.contains(syscall)
    }

    /// Add a device
    pub fn add_device(&mut self, device: &str) -> Result<()> {
        self.devices.insert(device.to_string());
        Ok(())
    }

    /// Remove a device
    pub fn remove_device(&mut self, device: &str) -> Result<()> {
        self.devices.remove(device);
        Ok(())
    }

    /// Check if a device is allowed
    pub fn has_device(&self, device: &str) -> bool {
        self.devices.contains(device)
    }

    /// Add a mount
    pub fn add_mount(&mut self, mount: &str) -> Result<()> {
        self.mounts.insert(mount.to_string());
        Ok(())
    }

    /// Remove a mount
    pub fn remove_mount(&mut self, mount: &str) -> Result<()> {
        self.mounts.remove(mount);
        Ok(())
    }

    /// Check if a mount is allowed
    pub fn has_mount(&self, mount: &str) -> bool {
        self.mounts.contains(mount)
    }

    /// Add a network
    pub fn add_network(&mut self, network: &str) -> Result<()> {
        self.networks.insert(network.to_string());
        Ok(())
    }

    /// Remove a network
    pub fn remove_network(&mut self, network: &str) -> Result<()> {
        self.networks.remove(network);
        Ok(())
    }

    /// Check if a network is allowed
    pub fn has_network(&self, network: &str) -> bool {
        self.networks.contains(network)
    }

    /// Add an allowed UID
    pub fn add_allowed_uid(&mut self, uid: u32) -> Result<()> {
        self.allowed_uids.insert(uid);
        Ok(())
    }

    /// Remove an allowed UID
    pub fn remove_allowed_uid(&mut self, uid: &u32) -> Result<()> {
        self.allowed_uids.remove(uid);
        Ok(())
    }

    /// Check if a UID is allowed
    pub fn has_allowed_uid(&self, uid: &u32) -> bool {
        self.allowed_uids.contains(uid)
    }

    /// Add an allowed GID
    pub fn add_allowed_gid(&mut self, gid: u32) -> Result<()> {
        self.allowed_gids.insert(gid);
        Ok(())
    }

    /// Remove an allowed GID
    pub fn remove_allowed_gid(&mut self, gid: &u32) -> Result<()> {
        self.allowed_gids.remove(gid);
        Ok(())
    }

    /// Check if a GID is allowed
    pub fn has_allowed_gid(&self, gid: &u32) -> bool {
        self.allowed_gids.contains(gid)
    }
}

/// Encryption algorithm
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    /// AES-256-GCM
    AES256GCM,
    /// ChaCha20-Poly1305
    ChaCha20Poly1305,
    /// TLS 1.3
    TLS13,
    /// Custom algorithm
    Custom,
}

impl std::fmt::Display for EncryptionAlgorithm {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncryptionAlgorithm::AES256GCM => write!(f, "aes256gcm"),
            EncryptionAlgorithm::ChaCha20Poly1305 => write!(f, "chacha20poly1305"),
            EncryptionAlgorithm::TLS13 => write!(f, "tls13"),
            EncryptionAlgorithm::Custom => write!(f, "custom"),
        }
    }
}

/// Authentication type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuthenticationType {
    /// None
    None,
    /// Basic
    Basic,
    /// Token
    Token,
    /// Certificate
    Certificate,
    /// mTLS
    MTLS,
    /// Custom
    Custom,
}

impl std::fmt::Display for AuthenticationType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthenticationType::None => write!(f, "none"),
            AuthenticationType::Basic => write!(f, "basic"),
            AuthenticationType::Token => write!(f, "token"),
            AuthenticationType::Certificate => write!(f, "certificate"),
            AuthenticationType::MTLS => write!(f, "mtls"),
            AuthenticationType::Custom => write!(f, "custom"),
        }
    }
}

/// Security policy
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityPolicy {
    /// Policy ID
    pub id: String,
    /// Policy name
    pub name: String,
    /// Security profiles
    pub profiles: HashMap<String, SecurityProfile>,
    /// Default profile
    pub default_profile: String,
    /// Encryption algorithm
    pub encryption_algorithm: EncryptionAlgorithm,
    /// Authentication type
    pub authentication_type: AuthenticationType,
    /// Policy creation time
    pub created_at: u64,
    /// Policy labels
    pub labels: HashMap<String, String>,
    /// Policy annotations
    pub annotations: HashMap<String, String>,
    /// Custom policy options
    pub custom: HashMap<String, String>,
}

impl SecurityPolicy {
    /// Create a new security policy
    pub fn new(name: &str) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Create default profiles
        let mut profiles = HashMap::new();

        let privileged_profile = SecurityProfile::new("privileged", SecurityProfileType::Privileged);
        let restricted_profile = SecurityProfile::new("restricted", SecurityProfileType::Restricted);
        let unprivileged_profile =
            SecurityProfile::new("unprivileged", SecurityProfileType::Unprivileged);

        profiles.insert(privileged_profile.id.clone(), privileged_profile);
        profiles.insert(restricted_profile.id.clone(), restricted_profile);
        profiles.insert(unprivileged_profile.id.clone(), unprivileged_profile);

        Self {
            id: uuid::Uuid::new_v4().to_string(),
            name: name.to_string(),
            profiles,
            default_profile: unprivileged_profile.id,
            encryption_algorithm: EncryptionAlgorithm::TLS13,
            authentication_type: AuthenticationType::MTLS,
            created_at: now,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            custom: HashMap::new(),
        }
    }

    /// Add a security profile
    pub fn add_profile(&mut self, profile: SecurityProfile) -> Result<()> {
        // Check if profile already exists
        if self.profiles.contains_key(&profile.id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "security_profile".to_string(),
                id: profile.id.clone(),
            });
        }

        self.profiles.insert(profile.id.clone(), profile);
        Ok(())
    }

    /// Remove a security profile
    pub fn remove_profile(&mut self, profile_id: &str) -> Result<SecurityProfile> {
        // Check if profile is the default profile
        if profile_id == self.default_profile {
            return Err(ForgeError::InvalidOperationError {
                operation: "remove_profile".to_string(),
                reason: "Cannot remove default profile".to_string(),
            });
        }

        // Remove profile
        let profile = self.profiles.remove(profile_id).ok_or(ForgeError::NotFoundError {
            resource: "security_profile".to_string(),
            id: profile_id.to_string(),
        })?;

        Ok(profile)
    }

    /// Get a security profile
    pub fn get_profile(&self, profile_id: &str) -> Result<&SecurityProfile> {
        self.profiles.get(profile_id).ok_or(ForgeError::NotFoundError {
            resource: "security_profile".to_string(),
            id: profile_id.to_string(),
        })
    }

    /// Get a mutable security profile
    pub fn get_profile_mut(&mut self, profile_id: &str) -> Result<&mut SecurityProfile> {
        self.profiles
            .get_mut(profile_id)
            .ok_or(ForgeError::NotFoundError {
                resource: "security_profile".to_string(),
                id: profile_id.to_string(),
            })
    }

    /// Get the default security profile
    pub fn get_default_profile(&self) -> Result<&SecurityProfile> {
        self.get_profile(&self.default_profile)
    }

    /// Set the default security profile
    pub fn set_default_profile(&mut self, profile_id: &str) -> Result<()> {
        // Check if profile exists
        if !self.profiles.contains_key(profile_id) {
            return Err(ForgeError::NotFoundError {
                resource: "security_profile".to_string(),
                id: profile_id.to_string(),
            });
        }

        self.default_profile = profile_id.to_string();
        Ok(())
    }

    /// List all security profiles
    pub fn list_profiles(&self) -> Vec<&SecurityProfile> {
        self.profiles.values().collect()
    }
}

/// Container security context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityContext {
    /// Container ID
    pub container_id: String,
    /// Security profile ID
    pub profile_id: String,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
    /// Supplementary group IDs
    pub supplementary_gids: Vec<u32>,
    /// SELinux context
    pub selinux_context: Option<String>,
    /// AppArmor profile
    pub apparmor_profile: Option<String>,
    /// Seccomp profile
    pub seccomp_profile: Option<String>,
    /// No new privileges flag
    pub no_new_privileges: bool,
    /// Read-only root filesystem
    pub read_only_root_fs: bool,
    /// Run as non-root
    pub run_as_non_root: bool,
    /// Allowed capabilities
    pub capabilities: HashSet<Capability>,
    /// Context creation time
    pub created_at: u64,
    /// Custom context options
    pub custom: HashMap<String, String>,
}

impl SecurityContext {
    /// Create a new security context
    pub fn new(container_id: &str, profile: &SecurityProfile) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            container_id: container_id.to_string(),
            profile_id: profile.id.clone(),
            uid: 1000,
            gid: 1000,
            supplementary_gids: vec![],
            selinux_context: profile.selinux_context.clone(),
            apparmor_profile: profile.apparmor_profile.clone(),
            seccomp_profile: profile.seccomp_profile.clone(),
            no_new_privileges: profile.no_new_privileges,
            read_only_root_fs: profile.read_only_root_fs,
            run_as_non_root: profile.run_as_non_root,
            capabilities: profile.capabilities.clone(),
            created_at: now,
            custom: HashMap::new(),
        }
    }

    /// Check if a capability is allowed
    pub fn has_capability(&self, capability: &Capability) -> bool {
        self.capabilities.contains(capability)
    }

    /// Add a capability
    pub fn add_capability(&mut self, capability: Capability) -> Result<()> {
        self.capabilities.insert(capability);
        Ok(())
    }

    /// Remove a capability
    pub fn remove_capability(&mut self, capability: &Capability) -> Result<()> {
        self.capabilities.remove(capability);
        Ok(())
    }
}

/// Security manager
#[derive(Debug)]
pub struct SecurityManager {
    /// Security policies
    policies: Arc<RwLock<HashMap<String, SecurityPolicy>>>,
    /// Container security contexts
    contexts: Arc<RwLock<HashMap<String, SecurityContext>>>,
    /// Default policy
    default_policy: Arc<RwLock<String>>,
}

impl SecurityManager {
    /// Create a new security manager
    pub fn new() -> Self {
        // Create default policy
        let default_policy = SecurityPolicy::new("default");
        let default_policy_id = default_policy.id.clone();

        // Create policies map
        let mut policies = HashMap::new();
        policies.insert(default_policy_id.clone(), default_policy);

        Self {
            policies: Arc::new(RwLock::new(policies)),
            contexts: Arc::new(RwLock::new(HashMap::new())),
            default_policy: Arc::new(RwLock::new(default_policy_id)),
        }
    }

    /// Create a security policy
    pub fn create_policy(&self, name: &str) -> Result<SecurityPolicy> {
        let span = ExecutionSpan::new(
            "create_policy",
            common::identity::IdentityContext::system(),
        );

        let policy = SecurityPolicy::new(name);

        // Add policy to policies map
        let mut policies = self.policies.write().map_err(|_| ForgeError::LockError {
            resource: "policies".to_string(),
        })?;

        // Check if policy already exists
        if policies.contains_key(&policy.id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "security_policy".to_string(),
                id: policy.id.clone(),
            });
        }

        policies.insert(policy.id.clone(), policy.clone());

        Ok(policy)
    }

    /// Get a security policy
    pub fn get_policy(&self, policy_id: &str) -> Result<SecurityPolicy> {
        let span = ExecutionSpan::new(
            "get_policy",
            common::identity::IdentityContext::system(),
        );

        let policies = self.policies.read().map_err(|_| ForgeError::LockError {
            resource: "policies".to_string(),
        })?;

        let policy = policies.get(policy_id).ok_or(ForgeError::NotFoundError {
            resource: "security_policy".to_string(),
            id: policy_id.to_string(),
        })?;

        Ok(policy.clone())
    }

    /// Update a security policy
    pub fn update_policy(&self, policy: SecurityPolicy) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_policy",
            common::identity::IdentityContext::system(),
        );

        let mut policies = self.policies.write().map_err(|_| ForgeError::LockError {
            resource: "policies".to_string(),
        })?;

        if !policies.contains_key(&policy.id) {
            return Err(ForgeError::NotFoundError {
                resource: "security_policy".to_string(),
                id: policy.id.clone(),
            });
        }

        policies.insert(policy.id.clone(), policy);

        Ok(())
    }

    /// Remove a security policy
    pub fn remove_policy(&self, policy_id: &str) -> Result<SecurityPolicy> {
        let span = ExecutionSpan::new(
            "remove_policy",
            common::identity::IdentityContext::system(),
        );

        // Check if policy is the default policy
        let default_policy = self.default_policy.read().map_err(|_| ForgeError::LockError {
            resource: "default_policy".to_string(),
        })?;

        if policy_id == *default_policy {
            return Err(ForgeError::InvalidOperationError {
                operation: "remove_policy".to_string(),
                reason: "Cannot remove default policy".to_string(),
            });
        }

        // Remove policy
        let mut policies = self.policies.write().map_err(|_| ForgeError::LockError {
            resource: "policies".to_string(),
        })?;

        let policy = policies.remove(policy_id).ok_or(ForgeError::NotFoundError {
            resource: "security_policy".to_string(),
            id: policy_id.to_string(),
        })?;

        Ok(policy)
    }

    /// List all security policies
    pub fn list_policies(&self) -> Result<Vec<SecurityPolicy>> {
        let span = ExecutionSpan::new(
            "list_policies",
            common::identity::IdentityContext::system(),
        );

        let policies = self.policies.read().map_err(|_| ForgeError::LockError {
            resource: "policies".to_string(),
        })?;

        Ok(policies.values().cloned().collect())
    }

    /// Get the default security policy
    pub fn get_default_policy(&self) -> Result<SecurityPolicy> {
        let span = ExecutionSpan::new(
            "get_default_policy",
            common::identity::IdentityContext::system(),
        );

        let default_policy_id = self.default_policy.read().map_err(|_| ForgeError::LockError {
            resource: "default_policy".to_string(),
        })?;

        self.get_policy(&default_policy_id)
    }

    /// Set the default security policy
    pub fn set_default_policy(&self, policy_id: &str) -> Result<()> {
        let span = ExecutionSpan::new(
            "set_default_policy",
            common::identity::IdentityContext::system(),
        );

        // Check if policy exists
        let policies = self.policies.read().map_err(|_| ForgeError::LockError {
            resource: "policies".to_string(),
        })?;

        if !policies.contains_key(policy_id) {
            return Err(ForgeError::NotFoundError {
                resource: "security_policy".to_string(),
                id: policy_id.to_string(),
            });
        }

        // Set default policy
        let mut default_policy = self.default_policy.write().map_err(|_| ForgeError::LockError {
            resource: "default_policy".to_string(),
        })?;

        *default_policy = policy_id.to_string();

        Ok(())
    }

    /// Create a security context for a container
    pub fn create_context(
        &self,
        container_id: &str,
        policy_id: Option<&str>,
        profile_id: Option<&str>,
    ) -> Result<SecurityContext> {
        let span = ExecutionSpan::new(
            "create_context",
            common::identity::IdentityContext::system(),
        );

        // Get policy
        let policy = match policy_id {
            Some(id) => self.get_policy(id)?,
            None => self.get_default_policy()?,
        };

        // Get profile
        let profile = match profile_id {
            Some(id) => policy.get_profile(id)?,
            None => policy.get_default_profile()?,
        };

        // Create context
        let context = SecurityContext::new(container_id, profile);

        // Add context to contexts map
        let mut contexts = self.contexts.write().map_err(|_| ForgeError::LockError {
            resource: "contexts".to_string(),
        })?;

        // Check if context already exists
        if contexts.contains_key(container_id) {
            return Err(ForgeError::AlreadyExistsError {
                resource: "security_context".to_string(),
                id: container_id.to_string(),
            });
        }

        contexts.insert(container_id.to_string(), context.clone());

        Ok(context)
    }

    /// Get a security context
    pub fn get_context(&self, container_id: &str) -> Result<SecurityContext> {
        let span = ExecutionSpan::new(
            "get_context",
            common::identity::IdentityContext::system(),
        );

        let contexts = self.contexts.read().map_err(|_| ForgeError::LockError {
            resource: "contexts".to_string(),
        })?;

        let context = contexts.get(container_id).ok_or(ForgeError::NotFoundError {
            resource: "security_context".to_string(),
            id: container_id.to_string(),
        })?;

        Ok(context.clone())
    }

    /// Update a security context
    pub fn update_context(&self, context: SecurityContext) -> Result<()> {
        let span = ExecutionSpan::new(
            "update_context",
            common::identity::IdentityContext::system(),
        );

        let mut contexts = self.contexts.write().map_err(|_| ForgeError::LockError {
            resource: "contexts".to_string(),
        })?;

        if !contexts.contains_key(&context.container_id) {
            return Err(ForgeError::NotFoundError {
                resource: "security_context".to_string(),
                id: context.container_id.clone(),
            });
        }

        contexts.insert(context.container_id.clone(), context);

        Ok(())
    }

    /// Remove a security context
    pub fn remove_context(&self, container_id: &str) -> Result<SecurityContext> {
        let span = ExecutionSpan::new(
            "remove_context",
            common::identity::IdentityContext::system(),
        );

        let mut contexts = self.contexts.write().map_err(|_| ForgeError::LockError {
            resource: "contexts".to_string(),
        })?;

        let context = contexts.remove(container_id).ok_or(ForgeError::NotFoundError {
            resource: "security_context".to_string(),
            id: container_id.to_string(),
        })?;

        Ok(context)
    }

    /// List all security contexts
    pub fn list_contexts(&self) -> Result<Vec<SecurityContext>> {
        let span = ExecutionSpan::new(
            "list_contexts",
            common::identity::IdentityContext::system(),
        );

        let contexts = self.contexts.read().map_err(|_| ForgeError::LockError {
            resource: "contexts".to_string(),
        })?;

        Ok(contexts.values().cloned().collect())
    }

    /// Check if a container has a capability
    pub fn has_capability(&self, container_id: &str, capability: &Capability) -> Result<bool> {
        let span = ExecutionSpan::new(
            "has_capability",
            common::identity::IdentityContext::system(),
        );

        let context = self.get_context(container_id)?;
        Ok(context.has_capability(capability))
    }

    /// Validate a security operation
    pub fn validate_operation(
        &self,
        container_id: &str,
        operation: &str,
        required_capabilities: &[Capability],
    ) -> Result<bool> {
        let span = ExecutionSpan::new(
            "validate_operation",
            common::identity::IdentityContext::system(),
        );

        let context = self.get_context(container_id)?;

        // Check if all required capabilities are present
        for capability in required_capabilities {
            if !context.has_capability(capability) {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

/// Global security manager instance
static mut SECURITY_MANAGER: Option<SecurityManager> = None;

/// Initialize the security manager
pub fn init() -> Result<()> {
    let span = ExecutionSpan::new(
        "init_security_manager",
        common::identity::IdentityContext::system(),
    );

    // Create security manager
    let security_manager = SecurityManager::new();

    // Store the security manager
    unsafe {
        if SECURITY_MANAGER.is_none() {
            SECURITY_MANAGER = Some(security_manager);
        } else {
            return Err(ForgeError::AlreadyExistsError {
                resource: "security_manager".to_string(),
                id: "global".to_string(),
            });
        }
    }

    Ok(())
}

/// Get the security manager
pub fn get_security_manager() -> Result<&'static SecurityManager> {
    unsafe {
        match &SECURITY_MANAGER {
            Some(security_manager) => Ok(security_manager),
            None => Err(ForgeError::UninitializedError {
                component: "security_manager".to_string(),
            }),
        }
    }
}

/// Create a security policy
pub fn create_policy(name: &str) -> Result<SecurityPolicy> {
    let security_manager = get_security_manager()?;
    security_manager.create_policy(name)
}

/// Create a security context for a container
pub fn create_context(
    container_id: &str,
    policy_id: Option<&str>,
    profile_id: Option<&str>,
) -> Result<SecurityContext> {
    let security_manager = get_security_manager()?;
    security_manager.create_context(container_id, policy_id, profile_id)
}

/// Check if a container has a capability
pub fn has_capability(container_id: &str, capability: &Capability) -> Result<bool> {
    let security_manager = get_security_manager()?;
    security_manager.has_capability(container_id, capability)
}

/// Validate a security operation
pub fn validate_operation(
    container_id: &str,
    operation: &str,
    required_capabilities: &[Capability],
) -> Result<bool> {
    let security_manager = get_security_manager()?;
    security_manager.validate_operation(container_id, operation, required_capabilities)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_profile() {
        // Create privileged profile
        let mut profile = SecurityProfile::new("test-privileged", SecurityProfileType::Privileged);

        // Check profile fields
        assert_eq!(profile.name, "test-privileged");
        assert_eq!(profile.profile_type, SecurityProfileType::Privileged);
        assert_eq!(profile.isolation_level, IsolationLevel::Process);
        assert!(profile.has_capability(&Capability::SYS_ADMIN));
        assert!(!profile.no_new_privileges);
        assert!(!profile.read_only_root_fs);
        assert!(!profile.run_as_non_root);

        // Remove a capability
        profile.remove_capability(&Capability::SYS_ADMIN).unwrap();
        assert!(!profile.has_capability(&Capability::SYS_ADMIN));

        // Add a capability
        profile.add_capability(Capability::SYS_ADMIN).unwrap();
        assert!(profile.has_capability(&Capability::SYS_ADMIN));

        // Add a syscall
        profile.add_syscall("clone").unwrap();
        assert!(profile.has_syscall("clone"));

        // Remove a syscall
        profile.remove_syscall("clone").unwrap();
        assert!(!profile.has_syscall("clone"));

        // Add a device
        profile.add_device("/dev/null").unwrap();
        assert!(profile.has_device("/dev/null"));

        // Remove a device
        profile.remove_device("/dev/null").unwrap();
        assert!(!profile.has_device("/dev/null"));

        // Add a mount
        profile.add_mount("/tmp").unwrap();
        assert!(profile.has_mount("/tmp"));

        // Remove a mount
        profile.remove_mount("/tmp").unwrap();
        assert!(!profile.has_mount("/tmp"));

        // Add a network
        profile.add_network("bridge").unwrap();
        assert!(profile.has_network("bridge"));

        // Remove a network
        profile.remove_network("bridge").unwrap();
        assert!(!profile.has_network("bridge"));

        // Add an allowed UID
        profile.add_allowed_uid(1000).unwrap();
        assert!(profile.has_allowed_uid(&1000));

        // Remove an allowed UID
        profile.remove_allowed_uid(&1000).unwrap();
        assert!(!profile.has_allowed_uid(&1000));

        // Add an allowed GID
        profile.add_allowed_gid(1000).unwrap();
        assert!(profile.has_allowed_gid(&1000));

        // Remove an allowed GID
        profile.remove_allowed_gid(&1000).unwrap();
        assert!(!profile.has_allowed_gid(&1000));
    }

    #[test]
    fn test_security_policy() {
        // Create policy
        let mut policy = SecurityPolicy::new("test-policy");

        // Check policy fields
        assert_eq!(policy.name, "test-policy");
        assert_eq!(policy.profiles.len(), 3); // privileged, restricted, unprivileged
        assert_eq!(policy.encryption_algorithm, EncryptionAlgorithm::TLS13);
        assert_eq!(policy.authentication_type, AuthenticationType::MTLS);

        // Get default profile
        let default_profile = policy.get_default_profile().unwrap();
        assert_eq!(default_profile.profile_type, SecurityProfileType::Unprivileged);

        // Add a custom profile
        let custom_profile = SecurityProfile::new("custom", SecurityProfileType::Custom);
        policy.add_profile(custom_profile.clone()).unwrap();

        // Get the custom profile
        let retrieved_profile = policy.get_profile(&custom_profile.id).unwrap();
        assert_eq!(retrieved_profile.name, "custom");

        // Set the custom profile as default
        policy.set_default_profile(&custom_profile.id).unwrap();
        assert_eq!(policy.default_profile, custom_profile.id);

        // List profiles
        let profiles = policy.list_profiles();
        assert_eq!(profiles.len(), 4); // privileged, restricted, unprivileged, custom

        // Remove the custom profile (should fail as it's the default)
        let result = policy.remove_profile(&custom_profile.id);
        assert!(result.is_err());

        // Set another profile as default
        let unprivileged_profile = policy
            .profiles
            .values()
            .find(|p| p.profile_type == SecurityProfileType::Unprivileged)
            .unwrap();
        policy.set_default_profile(&unprivileged_profile.id).unwrap();

        // Now remove the custom profile
        let removed_profile = policy.remove_profile(&custom_profile.id).unwrap();
        assert_eq!(removed_profile.id, custom_profile.id);

        // Check that the profile was removed
        let profiles = policy.list_profiles();
        assert_eq!(profiles.len(), 3); // privileged, restricted, unprivileged
    }

    #[test]
    fn test_security_context() {
        // Create profile
        let profile = SecurityProfile::new("test-profile", SecurityProfileType::Restricted);

        // Create context
        let mut context = SecurityContext::new("test-container", &profile);

        // Check context fields
        assert_eq!(context.container_id, "test-container");
        assert_eq!(context.profile_id, profile.id);
        assert_eq!(context.uid, 1000);
        assert_eq!(context.gid, 1000);
        assert!(context.supplementary_gids.is_empty());
        assert!(context.no_new_privileges);
        assert!(!context.read_only_root_fs);
        assert!(!context.run_as_non_root);

        // Check capabilities
        assert!(context.has_capability(&Capability::CHOWN));
        assert!(context.has_capability(&Capability::DAC_OVERRIDE));
        assert!(context.has_capability(&Capability::FOWNER));
        assert!(context.has_capability(&Capability::FSETID));
        assert!(context.has_capability(&Capability::NET_BIND_SERVICE));
        assert!(context.has_capability(&Capability::SETUID));
        assert!(!context.has_capability(&Capability::SYS_ADMIN));

        // Remove a capability
        context.remove_capability(&Capability::CHOWN).unwrap();
        assert!(!context.has_capability(&Capability::CHOWN));

        // Add a capability
        context.add_capability(Capability::CHOWN).unwrap();
        assert!(context.has_capability(&Capability::CHOWN));
    }

    #[test]
    fn test_security_manager() {
        // Initialize security manager
        init().unwrap();
        let security_manager = get_security_manager().unwrap();

        // Create a policy
        let policy = security_manager.create_policy("test-policy").unwrap();
        assert_eq!(policy.name, "test-policy");

        // Get the policy
        let retrieved_policy = security_manager.get_policy(&policy.id).unwrap();
        assert_eq!(retrieved_policy.id, policy.id);

        // Create a context
        let context = security_manager
            .create_context("test-container", Some(&policy.id), None)
            .unwrap();
        assert_eq!(context.container_id, "test-container");

        // Get the context
        let retrieved_context = security_manager.get_context("test-container").unwrap();
        assert_eq!(retrieved_context.container_id, "test-container");

        // Check capability
        let has_capability = security_manager
            .has_capability("test-container", &Capability::NET_BIND_SERVICE)
            .unwrap();
        assert!(has_capability);

        // Validate operation
        let is_valid = security_manager
            .validate_operation(
                "test-container",
                "bind_port",
                &[Capability::NET_BIND_SERVICE],
            )
            .unwrap();
        assert!(is_valid);

        // Validate operation (should fail)
        let is_valid = security_manager
            .validate_operation(
                "test-container",
                "mount",
                &[Capability::SYS_ADMIN],
            )
            .unwrap();
        assert!(!is_valid);

        // Update context
        let mut updated_context = retrieved_context.clone();
        updated_context.add_capability(Capability::SYS_ADMIN).unwrap();
        security_manager.update_context(updated_context).unwrap();

        // Validate operation again (should succeed now)
        let is_valid = security_manager
            .validate_operation(
                "test-container",
                "mount",
                &[Capability::SYS_ADMIN],
            )
            .unwrap();
        assert!(is_valid);

        // Remove context
        let removed_context = security_manager.remove_context("test-container").unwrap();
        assert_eq!(removed_context.container_id, "test-container");

        // Check that context was removed
        let result = security_manager.get_context("test-container");
        assert!(result.is_err());

        // Remove policy
        let removed_policy = security_manager.remove_policy(&policy.id).unwrap();
        assert_eq!(removed_policy.id, policy.id);

        // Check that policy was removed
        let result = security_manager.get_policy(&policy.id);
        assert!(result.is_err());
    }
}