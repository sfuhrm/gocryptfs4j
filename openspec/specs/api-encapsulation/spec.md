# api-encapsulation Specification

## Purpose

Defines how library types expose their internal state so that every non-constant
field is private and state is reachable only through accessors when a client
needs it.

## Requirements

### Requirement: Non-constant instance fields are private

Every non-constant instance field of a library type SHALL be declared
`private`. State SHALL NOT be exposed as a directly readable or writable
public or package-accessible field.

#### Scenario: No public mutable state

- **WHEN** a client inspects the public API of any library type
- **THEN** no non-constant instance field is directly accessible from outside
  the declaring class

#### Scenario: Internal data holders are private too

- **WHEN** a type used only inside the library (not part of the public API)
  holds state
- **THEN** its state fields are `private` and not readable as fields from other
  classes

### Requirement: State is exposed only through accessors when needed

A field's value SHALL be exposed to clients through an accessor method only
when that value is genuinely needed outside the declaring type. Where a value
is not needed by a client, no accessor SHALL be provided.

#### Scenario: Accessor provided for needed state

- **WHEN** a client legitimately needs to read a value held by a library type
- **THEN** the value is available through an accessor method, not a field

#### Scenario: No accessor for internal state

- **WHEN** a value is used only internally by the declaring type or its package
- **THEN** the type exposes no accessor for that value to library clients

### Requirement: Objects act on their own state

Where the tell-don't-ask principle applies, a library type SHALL provide
behavior that acts on its own state, rather than requiring a client to read
state out and act on it themselves.

#### Scenario: Behavior stays on the owning object

- **WHEN** an operation needs data held by a library object
- **THEN** the object performs the operation itself instead of exposing the
  data for the client to manipulate

### Requirement: Immutable constants remain public

Immutable `static final` constants (protocol constants, sizes, feature-flag
names and similar) SHALL remain `public` and are not subject to field
encapsulation.

#### Scenario: Constants are still accessible

- **WHEN** a client needs a documented constant such as a key length or flag
  name
- **THEN** that constant remains directly accessible as before
