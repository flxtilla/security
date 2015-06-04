package principal

type Permission interface {
	Tag() string
	Needs(...interface{}) Set
	Excludes(...interface{}) Set
	Allows(Identity) bool
	Requires(Identity) bool
}

type permission struct {
	tag      string
	needs    Set
	excludes Set
}

func NewPermission(tag string, needs ...interface{}) Permission {
	return &permission{
		tag:   tag,
		needs: NewSet(needs...),
	}
}

func (p *permission) Tag() string {
	return p.tag
}

func (p *permission) Needs(needs ...interface{}) Set {
	p.needs.Add(needs...)
	return p.needs
}

func (p *permission) Excludes(excludes ...interface{}) Set {
	p.excludes.Add(excludes...)
	return p.excludes
}

// Allows checks the intersection of permission needs and identity provides.
// Returns true if the intersection is not empty.
func (p *permission) Allows(i Identity) bool {
	return !Intersection(p.needs, i.Provides()).IsEmpty()
}

// Requires checks that given identity provides all that the Permission needs.
// Returns true if the identity has all the permission needs.
func (p *permission) Requires(i Identity) bool {
	return i.Provides().Has(p.Needs().List()...)
}
