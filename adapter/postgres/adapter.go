package postgres

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/casbin/casbin/v2/model"
	"github.com/casbin/casbin/v2/persist"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var _ persist.Adapter = (*Adapter)(nil)

// numColumns is the number of value columns (v0..v5), the Casbin convention.
const numColumns = 6

// identifierRE matches a safe, unquoted SQL identifier. Table and channel names
// cannot be passed as query parameters, so they are validated against this and
// interpolated directly. Anything else is rejected to prevent SQL injection.
var identifierRE = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

func validateIdentifier(kind, name string) error {
	if !identifierRE.MatchString(name) {
		return fmt.Errorf("postgres: invalid %s %q (must match [A-Za-z_][A-Za-z0-9_]*)", kind, name)
	}
	return nil
}

// Adapter is a Casbin persist.Adapter backed by PostgreSQL via pgx.
type Adapter struct {
	pool  *pgxpool.Pool
	table string
}

// Option configures an Adapter.
type Option func(*Adapter)

// WithTable sets the policy table name (default "casbin_rule"). The name must be
// a plain SQL identifier.
func WithTable(name string) Option {
	return func(a *Adapter) { a.table = name }
}

// New builds a PostgreSQL adapter over the given pool. It validates the table
// name and creates the table if it does not already exist.
func New(ctx context.Context, pool *pgxpool.Pool, opts ...Option) (*Adapter, error) {
	if pool == nil {
		return nil, fmt.Errorf("postgres: nil pool")
	}
	a := &Adapter{pool: pool, table: "casbin_rule"}
	for _, opt := range opts {
		opt(a)
	}
	if err := validateIdentifier("table name", a.table); err != nil {
		return nil, err
	}
	if err := a.createTable(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Adapter) createTable(ctx context.Context) error {
	cols := make([]string, numColumns)
	for i := 0; i < numColumns; i++ {
		cols[i] = fmt.Sprintf("v%d TEXT NOT NULL DEFAULT ''", i)
	}
	q := fmt.Sprintf(
		"CREATE TABLE IF NOT EXISTS %s (id BIGSERIAL PRIMARY KEY, ptype TEXT NOT NULL, %s)",
		a.table, strings.Join(cols, ", "),
	)
	if _, err := a.pool.Exec(ctx, q); err != nil {
		return fmt.Errorf("postgres: create table: %w", err)
	}
	return nil
}

// --- pure helpers (unit-tested without a database) ---

// ruleToColumns maps a Casbin value rule (the tokens after ptype) into the fixed
// v0..v5 columns, padding the rest with "". It errors if the rule is too wide.
func ruleToColumns(rule []string) ([numColumns]string, error) {
	var cols [numColumns]string
	if len(rule) > numColumns {
		return cols, fmt.Errorf("postgres: rule has %d values, max %d", len(rule), numColumns)
	}
	for i, v := range rule {
		cols[i] = v
	}
	return cols, nil
}

// buildRuleArray reconstructs a Casbin policy array (ptype + values) from a row,
// dropping trailing empty value columns so variable-arity policies round-trip.
func buildRuleArray(ptype string, cols []string) []string {
	end := len(cols)
	for end > 0 && cols[end-1] == "" {
		end--
	}
	out := make([]string, 0, end+1)
	out = append(out, ptype)
	out = append(out, cols[:end]...)
	return out
}

// filteredDelete builds the DELETE statement and args for RemoveFilteredPolicy.
// ptype is always matched; each non-empty fieldValue filters column v(fieldIndex+i).
// A non-empty value mapping outside v0..v5 is an error rather than a silently
// dropped condition, which would otherwise widen the DELETE (fail-open removal).
func filteredDelete(table, ptype string, fieldIndex int, fieldValues []string) (string, []any, error) {
	conds := []string{"ptype = $1"}
	args := []any{ptype}
	for i, v := range fieldValues {
		if v == "" {
			continue
		}
		col := fieldIndex + i
		if col < 0 || col >= numColumns {
			return "", nil, fmt.Errorf("postgres: filter index %d out of range [0,%d)", col, numColumns)
		}
		args = append(args, v)
		conds = append(conds, fmt.Sprintf("v%d = $%d", col, len(args)))
	}
	q := "DELETE FROM " + table + " WHERE " + strings.Join(conds, " AND ")
	return q, args, nil
}

// exactDelete builds the DELETE statement and args for RemovePolicy (every
// supplied value column must match exactly).
func exactDelete(table, ptype string, rule []string) (string, []any, error) {
	cols, err := ruleToColumns(rule)
	if err != nil {
		return "", nil, err
	}
	conds := []string{"ptype = $1"}
	args := []any{ptype}
	for i := 0; i < len(rule); i++ {
		args = append(args, cols[i])
		conds = append(conds, "v"+strconv.Itoa(i)+" = $"+strconv.Itoa(len(args)))
	}
	q := "DELETE FROM " + table + " WHERE " + strings.Join(conds, " AND ")
	return q, args, nil
}

// --- persist.Adapter implementation ---

// LoadPolicy loads all policy rules from the table into the model.
func (a *Adapter) LoadPolicy(m model.Model) error {
	ctx := context.Background()
	q := fmt.Sprintf("SELECT ptype, v0, v1, v2, v3, v4, v5 FROM %s", a.table)
	rows, err := a.pool.Query(ctx, q)
	if err != nil {
		return fmt.Errorf("postgres: load policy: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var ptype string
		cols := make([]string, numColumns)
		dest := []any{&ptype, &cols[0], &cols[1], &cols[2], &cols[3], &cols[4], &cols[5]}
		if err := rows.Scan(dest...); err != nil {
			return fmt.Errorf("postgres: scan policy row: %w", err)
		}
		if err := persist.LoadPolicyArray(buildRuleArray(ptype, cols), m); err != nil {
			return fmt.Errorf("postgres: load policy line: %w", err)
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("postgres: iterate policy rows: %w", err)
	}
	return nil
}

// SavePolicy replaces all stored rules with the model's current p and g policies.
func (a *Adapter) SavePolicy(m model.Model) error {
	ctx := context.Background()
	tx, err := a.pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("postgres: begin: %w", err)
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, "DELETE FROM "+a.table); err != nil {
		return fmt.Errorf("postgres: truncate: %w", err)
	}

	batch := &pgx.Batch{}
	queue := func(ptype string, rule []string) error {
		cols, err := ruleToColumns(rule)
		if err != nil {
			return err
		}
		batch.Queue(
			fmt.Sprintf("INSERT INTO %s (ptype, v0, v1, v2, v3, v4, v5) VALUES ($1,$2,$3,$4,$5,$6,$7)", a.table),
			ptype, cols[0], cols[1], cols[2], cols[3], cols[4], cols[5],
		)
		return nil
	}
	for _, sec := range []string{"p", "g"} {
		ast, ok := m[sec]
		if !ok {
			continue
		}
		for ptype, assertion := range ast {
			for _, rule := range assertion.Policy {
				if err := queue(ptype, rule); err != nil {
					return err
				}
			}
		}
	}

	if batch.Len() > 0 {
		br := tx.SendBatch(ctx, batch)
		for i := 0; i < batch.Len(); i++ {
			if _, err := br.Exec(); err != nil {
				_ = br.Close()
				return fmt.Errorf("postgres: insert policy: %w", err)
			}
		}
		if err := br.Close(); err != nil {
			return fmt.Errorf("postgres: close batch: %w", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("postgres: commit: %w", err)
	}
	return nil
}

// AddPolicy inserts a single policy rule.
func (a *Adapter) AddPolicy(_ string, ptype string, rule []string) error {
	ctx := context.Background()
	cols, err := ruleToColumns(rule)
	if err != nil {
		return err
	}
	q := fmt.Sprintf("INSERT INTO %s (ptype, v0, v1, v2, v3, v4, v5) VALUES ($1,$2,$3,$4,$5,$6,$7)", a.table)
	if _, err := a.pool.Exec(ctx, q, ptype, cols[0], cols[1], cols[2], cols[3], cols[4], cols[5]); err != nil {
		return fmt.Errorf("postgres: add policy: %w", err)
	}
	return nil
}

// RemovePolicy deletes a single policy rule (all supplied columns must match).
func (a *Adapter) RemovePolicy(_ string, ptype string, rule []string) error {
	ctx := context.Background()
	q, args, err := exactDelete(a.table, ptype, rule)
	if err != nil {
		return err
	}
	if _, err := a.pool.Exec(ctx, q, args...); err != nil {
		return fmt.Errorf("postgres: remove policy: %w", err)
	}
	return nil
}

// RemoveFilteredPolicy deletes rules matching ptype and the non-empty field
// values starting at fieldIndex.
func (a *Adapter) RemoveFilteredPolicy(_ string, ptype string, fieldIndex int, fieldValues ...string) error {
	ctx := context.Background()
	q, args, err := filteredDelete(a.table, ptype, fieldIndex, fieldValues)
	if err != nil {
		return err
	}
	if _, err := a.pool.Exec(ctx, q, args...); err != nil {
		return fmt.Errorf("postgres: remove filtered policy: %w", err)
	}
	return nil
}
