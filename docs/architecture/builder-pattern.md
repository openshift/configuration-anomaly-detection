# Builder Pattern Architecture

## Overview

The Configuration Anomaly Detection (CAD) codebase uses the Builder pattern extensively to provide clean, type-safe, and composable interfaces for constructing complex objects. This document describes our current usage, conventions, and guidelines for working with and extending builders.

## Philosophy

Builders in CAD serve several key purposes:

1. **Progressive Construction**: Build complex objects step-by-step with clear intent
2. **Optional Dependencies**: Request only the resources you need
3. **Error Handling**: Centralize resource initialization and error handling
4. **Immutability**: Build once, use many times
5. **Fluent Interface**: Chain method calls for readability

## Current Builder Implementations

### 1. ResourceBuilder

**Location**: `pkg/investigations/investigation/investigation.go`

**Purpose**: Constructs investigation resources (cluster info, clients, notes) on-demand.

#### Interface

```go
type ResourceBuilder interface {
    WithCluster() ResourceBuilder
    WithClusterDeployment() ResourceBuilder
    WithAwsClient() ResourceBuilder
    WithK8sClient() ResourceBuilder
    WithNotes() ResourceBuilder
    Build() (*Resources, error)
}
```

#### Key Characteristics

- **Lazy Loading**: Resources are only fetched when explicitly requested
- **Dependency Chain**: Some resources depend on others (e.g., AWS client requires Cluster)
- **Caching**: Built resources are cached to avoid duplicate API calls
- **Partial Success**: Returns whatever was built successfully, even on error

#### Usage Example

```go
func (c *Investigation) Run(rb investigation.ResourceBuilder) (investigation.InvestigationResult, error) {
    // Request only what you need
    r, err := rb.
        WithCluster().
        WithAwsClient().
        WithNotes().
        Build()
    
    if err != nil {
        // Handle errors - r may contain partial results
        return investigation.InvestigationResult{}, err
    }
    
    // Use resources
    cluster := r.Cluster
    awsClient := r.AwsClient
    notes := r.Notes
    
    // ... investigation logic ...
}
```

#### Implementation Details

```go
type ResourceBuilderT struct {
    // Flags indicating what to build
    buildCluster           bool
    buildClusterDeployment bool
    buildAwsClient         bool
    buildK8sClient         bool
    buildNotes             bool
    buildLogger            bool
    
    // Input parameters
    clusterId    string
    name         string
    logLevel     string
    pipelineName string
    ocmClient    *ocm.SdkClient
    
    // Cached results
    builtResources *Resources
    buildErr       error
}
```

**Key Pattern**: Each `WithX()` method sets a boolean flag and returns the builder for chaining. The `Build()` method checks flags and constructs only requested resources.

#### Dependency Resolution

Resources have dependencies that are automatically satisfied:

- `WithAwsClient()` → automatically calls `WithCluster()`
- `WithClusterDeployment()` → automatically calls `WithCluster()`
- `WithK8sClient()` → no automatic dependencies

#### Error Handling Strategy

The ResourceBuilder uses **typed errors** to distinguish failure modes:

```go
// Typed errors for different resource failures
type ClusterNotFoundError struct {
    ClusterID string
    Err       error
}

type AWSClientError struct {
    ClusterID string
    Err       error
}

type K8SClientError struct {
    ClusterID string
    Err       error
}

type ClusterDeploymentNotFoundError struct {
    ClusterID string
    Err       error
}
```

Investigations can use `errors.As()` to handle specific failures:

```go
resources, err := rb.WithAwsClient().Build()

awsClientErr := &investigation.AWSClientError{}
if errors.As(err, awsClientErr) {
    // Handle AWS-specific failure
    // Note: resources.Cluster may still be valid!
}
```

### 2. OCM LimitedSupportReasonBuilder

**Location**: `pkg/ocm/ocm.go`

**Purpose**: Constructs OCM SDK limited support reason objects.

#### Implementation

```go
func newLimitedSupportReasonBuilder(ls *LimitedSupportReason) *cmv1.LimitedSupportReasonBuilder {
    builder := cmv1.NewLimitedSupportReason()
    builder.Summary(ls.Summary)
    builder.Details(ls.Details)
    builder.DetectionType(cmv1.DetectionTypeManual)
    return builder
}
```

**Note**: This is a thin wrapper around the OCM SDK's builder. We use it to ensure consistent defaults (like `DetectionType`).

### 3. OCM ServiceLog Builder Pattern

**Location**: `pkg/ocm/ocm.go`

**Purpose**: Constructs OCM SDK service log entries.

#### Implementation

```go
func (c *SdkClient) PostServiceLog(cluster *cmv1.Cluster, sl *ServiceLog) error {
    builder := &servicelogsv1.LogEntryBuilder{}
    builder.Severity(servicelogsv1.Severity(sl.Severity))
    builder.ServiceName(sl.ServiceName)
    builder.Summary(sl.Summary)
    builder.Description(sl.Description)
    builder.InternalOnly(sl.InternalOnly)
    builder.ClusterID(cluster.ID())
    
    le, err := builder.Build()
    if err != nil {
        return fmt.Errorf("could not create post request (SL): %w", err)
    }
    
    // Send the built object
    request := c.conn.ServiceLogs().V1().ClusterLogs().Add()
    request = request.Body(le)
    _, err = request.Send()
    return err
}
```

**Pattern**: Convert from our internal type to OCM SDK builder, set all fields, build, then send.

## Builder Pattern Conventions

### Naming Conventions

1. **Builder Types**: Suffix with `Builder` (e.g., `ResourceBuilder`, `ActionBuilder`)
2. **Builder Methods**: 
   - Prefix with `With` for adding optional components: `WithCluster()`, `WithAwsClient()`
   - Prefix with `Add` for adding items to collections: `AddAction()`, `AddDetail()`
   - Prefix with `Set` for required fields (rare, prefer constructor args)
3. **Finalization**: Always use `Build()` to get the final object

### Method Signatures

All builder methods should follow these patterns:

#### Fluent Chaining Pattern

```go
// Return the builder for chaining
func (b *Builder) WithX() *Builder {
    b.field = value
    return b
}
```

#### Adding Items Pattern

```go
// Return the builder for chaining
func (b *Builder) AddItem(item Item) *Builder {
    b.items = append(b.items, item)
    return b
}
```

#### Build Pattern

```go
// Return the constructed object and any error
func (b *Builder) Build() (Result, error) {
    // Validate
    if err := b.validate(); err != nil {
        return Result{}, err
    }
    
    // Construct
    return b.construct(), nil
}
```

### Constructor Pattern

Always provide a constructor function for builders:

```go
// NewXBuilder creates a new builder with required parameters
func NewXBuilder(required1 string, required2 int) *XBuilder {
    return &XBuilder{
        required1: required1,
        required2: required2,
        // Initialize optional fields with sensible defaults
        optionalField: defaultValue,
    }
}
```

**Rationale**: Required parameters go in constructor, optional ones use `WithX()` methods.

## Extending Builders

### Adding a New Resource to ResourceBuilder

**Scenario**: You want to add a new client type (e.g., BackplaneReportsClient) to ResourceBuilder.

#### Step 1: Add to Resources Struct

```go
type Resources struct {
    Name              string
    Cluster           *cmv1.Cluster
    ClusterDeployment *hivev1.ClusterDeployment
    AwsClient         aws.Client
    K8sClient         k8sclient.Client
    OcmClient         ocm.Client
    PdClient          pagerduty.Client
    Notes             *notewriter.NoteWriter
    
    // NEW: Add your resource
    BackplaneReportsClient reports.Client
}
```

#### Step 2: Add Flag to Builder Struct

```go
type ResourceBuilderT struct {
    buildCluster           bool
    buildClusterDeployment bool
    buildAwsClient         bool
    buildK8sClient         bool
    buildNotes             bool
    buildLogger            bool
    
    // NEW: Add your flag
    buildBackplaneReportsClient bool
    
    // ... other fields ...
}
```

#### Step 3: Add WithX Method

```go
func (r *ResourceBuilderT) WithBackplaneReportsClient() ResourceBuilder {
    r.buildBackplaneReportsClient = true
    
    // If your resource depends on others, call them:
    // r.WithCluster()
    
    return r
}
```

#### Step 4: Add Build Logic

```go
func (r *ResourceBuilderT) Build() (*Resources, error) {
    if r.buildErr != nil {
        return r.builtResources, r.buildErr
    }
    
    // ... existing build logic ...
    
    // NEW: Add your build logic
    if r.buildBackplaneReportsClient && r.builtResources.BackplaneReportsClient == nil {
        r.builtResources.BackplaneReportsClient, err = reports.NewClient(r.builtResources.Cluster.ID())
        if err != nil {
            r.buildErr = BackplaneReportsClientError{ClusterID: r.clusterId, Err: err}
            return r.builtResources, r.buildErr
        }
    }
    
    return r.builtResources, nil
}
```

#### Step 5: Add Typed Error (Optional but Recommended)

```go
type BackplaneReportsClientError struct {
    ClusterID string
    Err       error
}

func (e BackplaneReportsClientError) Error() string {
    return fmt.Sprintf("failed to create backplane reports client for cluster %s: %v", e.ClusterID, e.Err)
}

func (e BackplaneReportsClientError) Unwrap() error {
    return e.Err
}
```

### Creating a New Builder

**Scenario**: You need a builder for constructing investigation results.

#### Step 1: Define the Result Type

```go
type InvestigationResult struct {
    Findings *InvestigationFindings
    Actions  []Action
    Outcome  InvestigationOutcome
}
```

#### Step 2: Create Builder Struct

```go
type InvestigationResultBuilder struct {
    result *InvestigationResult
}
```

#### Step 3: Add Constructor

```go
func NewResultBuilder() *InvestigationResultBuilder {
    return &InvestigationResultBuilder{
        result: &InvestigationResult{
            Findings: &InvestigationFindings{
                MetricsLabels: make(map[string]string),
            },
            Actions: []Action{},
            Outcome: OutcomeContinue, // sensible default
        },
    }
}
```

#### Step 4: Add Fluent Methods

```go
// Simple field setter
func (b *InvestigationResultBuilder) WithSummary(summary string) *InvestigationResultBuilder {
    b.result.Findings.Summary = summary
    return b
}

// Adding to collection
func (b *InvestigationResultBuilder) AddAction(action Action) *InvestigationResultBuilder {
    b.result.Actions = append(b.result.Actions, action)
    return b
}

// Convenience wrapper
func (b *InvestigationResultBuilder) AddServiceLog(sl *ocm.ServiceLog, reason string) *InvestigationResultBuilder {
    return b.AddAction(&ServiceLogAction{
        ServiceLog: sl,
        Reason:     reason,
    })
}
```

#### Step 5: Add Build Method

```go
func (b *InvestigationResultBuilder) Build() InvestigationResult {
    // Optionally validate
    // if b.result.Findings.Summary == "" {
    //     panic("Summary is required") // or return error
    // }
    
    // Return value (not pointer) to prevent mutation after build
    return *b.result
}
```

## Best Practices

### 1. Return Values, Not Pointers from Build()

**Good**:
```go
func (b *Builder) Build() InvestigationResult {
    return *b.result  // Return value
}
```

**Why**: Prevents accidental mutation of the built object. Once built, it's immutable.

**Exception**: When the built object is inherently a pointer (like `*Resources`), return the pointer.

### 2. Initialize Collections in Constructor

**Good**:
```go
func NewBuilder() *Builder {
    return &Builder{
        items: []Item{},  // Initialize to empty slice, not nil
        labels: make(map[string]string),
    }
}
```

**Why**: Prevents nil pointer panics when appending/setting.

### 3. Use Typed Errors for Build Failures

**Good**:
```go
type ClusterNotFoundError struct {
    ClusterID string
    Err       error
}

func (r *ResourceBuilderT) Build() (*Resources, error) {
    cluster, err := r.ocmClient.GetClusterInfo(r.clusterId)
    if err != nil {
        return r.builtResources, ClusterNotFoundError{
            ClusterID: r.clusterId,
            Err:       err,
        }
    }
}
```

**Why**: Allows callers to handle different error types differently.

### 4. Provide Sensible Defaults

**Good**:
```go
func NewResultBuilder() *InvestigationResultBuilder {
    return &InvestigationResultBuilder{
        result: &InvestigationResult{
            Outcome: OutcomeContinue,  // Default to continue
            Severity: FindingSeverityInfo,  // Default severity
        },
    }
}
```

**Why**: Most use cases work with defaults; explicit overrides only when needed.

### 5. Document Dependencies

If `WithX()` automatically calls `WithY()`, document it:

```go
// WithAwsClient requests an AWS client for the cluster.
// This automatically calls WithCluster() as the cluster info is required.
func (r *ResourceBuilderT) WithAwsClient() ResourceBuilder {
    r.WithCluster()  // Automatic dependency
    r.buildAwsClient = true
    return r
}
```

### 6. Cache Built Resources

**Good** (ResourceBuilder pattern):
```go
func (r *ResourceBuilderT) Build() (*Resources, error) {
    // Check if already built
    if r.builtResources.Cluster != nil {
        return r.builtResources, r.buildErr
    }
    
    // Build and cache
    r.builtResources.Cluster, err = r.ocmClient.GetClusterInfo(r.clusterId)
    if err != nil {
        r.buildErr = err
        return r.builtResources, r.buildErr
    }
    
    return r.builtResources, nil
}
```

**Why**: Allows calling `Build()` multiple times without duplicate work. Important for ResourceBuilder since investigations call it multiple times.

### 7. Support Partial Success

**ResourceBuilder Pattern Only**:

```go
func (r *ResourceBuilderT) Build() (*Resources, error) {
    // Always return builtResources, even on error
    // Caller can access successfully built resources
    return r.builtResources, r.buildErr
}
```

**Why**: An investigation might still be able to run with partial resources. For example, if AWS client fails but cluster info succeeded, some checks can still run.

**Note**: This is specific to ResourceBuilder. Most builders should return zero-value on error.

## Testing Builders

### Testing Builder Itself

```go
func TestResourceBuilder(t *testing.T) {
    // Test successful build
    t.Run("successful cluster build", func(t *testing.T) {
        mockOcmClient := // ... create mock
        
        rb, _ := investigation.NewResourceBuilder(
            mockPdClient,
            mockOcmClient,
            "cluster-123",
            "test-investigation",
            "info",
            "test-pipeline",
        )
        
        resources, err := rb.WithCluster().Build()
        
        assert.NoError(t, err)
        assert.NotNil(t, resources.Cluster)
    })
    
    // Test error handling
    t.Run("cluster not found error", func(t *testing.T) {
        mockOcmClient := // ... mock to return error
        
        rb, _ := investigation.NewResourceBuilder(...)
        resources, err := rb.WithCluster().Build()
        
        var clusterErr *investigation.ClusterNotFoundError
        assert.True(t, errors.As(err, &clusterErr))
        assert.Equal(t, "cluster-123", clusterErr.ClusterID)
    })
}
```

### Mocking Builders in Tests

For investigations, use the mock implementation:

```go
func TestInvestigation(t *testing.T) {
    mockResources := &investigation.Resources{
        Cluster: mockCluster,
        AwsClient: mockAwsClient,
        Notes: notewriter.New("test", logger),
    }
    
    mockBuilder := &investigation.ResourceBuilderMock{
        Resources: mockResources,
        BuildError: nil,
    }
    
    result, err := investigation.Run(mockBuilder)
    
    // Assert on result
}
```

## Anti-Patterns to Avoid

### ❌ Don't: Mutate After Build

```go
// BAD
builder := NewResultBuilder()
result := builder.Build()
result.Actions = append(result.Actions, newAction)  // Mutating built result
```

**Solution**: Build returns a value copy, so this won't compile. But if you change to return pointer, don't do this.

### ❌ Don't: Build Multiple Objects from Same Builder

```go
// BAD
builder := NewResultBuilder().WithSummary("First")
result1 := builder.Build()

builder.WithSummary("Second")  // Trying to reuse builder
result2 := builder.Build()  // result1 is now corrupted
```

**Solution**: Create a new builder for each object.

### ❌ Don't: Mix Required and Optional in WithX Methods

```go
// BAD
func NewBuilder() *Builder {
    return &Builder{}  // Missing required fields
}

func (b *Builder) WithRequiredField(field string) *Builder {
    b.required = field  // Required fields should be in constructor
    return b
}
```

**Solution**: Required fields go in constructor, optional ones in `WithX()`.

### ❌ Don't: Return Errors from WithX Methods

```go
// BAD
func (b *Builder) WithValidatedField(field string) (*Builder, error) {
    if field == "" {
        return nil, errors.New("field required")
    }
    b.field = field
    return b, nil
}
```

**Solution**: Validation happens in `Build()`, not in `WithX()` methods. Keep the fluent interface clean.

### ❌ Don't: Have Side Effects in WithX Methods

```go
// BAD
func (r *ResourceBuilderT) WithCluster() ResourceBuilder {
    // DON'T fetch the cluster here
    cluster, err := r.ocmClient.GetClusterInfo(r.clusterId)
    r.builtResources.Cluster = cluster
    r.buildErr = err
    return r
}
```

**Solution**: `WithX()` should only set flags. `Build()` does the actual work.

## Future Directions

### Planned Builder Additions

1. **ActionBuilder**: For constructing actions in the new executor module
2. **ReportInputBuilder**: For building executor input with all context
3. **FindingsBuilder**: Potentially split from InvestigationResultBuilder for complex findings

### Builder Variants Being Considered

1. **Validated Builders**: Builders that enforce constraints at compile time using type states
2. **Async Builders**: Builders that can fetch resources concurrently
3. **Conditional Builders**: Builders with conditional logic (build X only if Y succeeded)

## References

- ResourceBuilder implementation: `pkg/investigations/investigation/investigation.go`
- Example usages: All files in `pkg/investigations/*/` 
- OCM builders: `pkg/ocm/ocm.go`
- Builder pattern discussion: https://golang.cafe/blog/golang-builder-pattern.html

## Questions?

For questions about builders or to propose a new builder, contact the CAD team or open a discussion in the repository.
