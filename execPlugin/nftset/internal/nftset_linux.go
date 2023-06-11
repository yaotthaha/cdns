//go:build linux

package internal

import (
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/google/nftables"
	"go4.org/netipx"
)

var (
	ErrInetMismatch = errors.New("nftset: address family mismatch")
	ErrConnClosed   = errors.New("conn is closed")
)

type NftSetLinux struct {
	typ   InetType
	table *nftables.Table
	set   *nftables.Set
	conn  *nftables.Conn
	lock  sync.Mutex
}

func New(tableName string, setName string, typ InetType) (*NftSetLinux, error) {
	conn, err := nftables.New()
	if err != nil {
		return nil, err
	}
	tables, err := conn.ListTables()
	if err != nil {
		return nil, err
	}
	var matchTable *nftables.Table
	for _, table := range tables {
		if table.Name == tableName {
			matchTable = table
			break
		}
	}
	if matchTable == nil {
		return nil, errors.New("nftset: table not found")
	}
	set, err := conn.GetSetByName(matchTable, setName)
	if err != nil {
		return nil, err
	}
	return &NftSetLinux{
		table: matchTable,
		set:   set,
		typ:   typ,
		conn:  conn,
	}, nil
}

func (n *NftSetLinux) Name() string {
	return fmt.Sprintf("%s-%s", n.table.Name, n.set.Name)
}

func (n *NftSetLinux) Close() error {
	n.lock.Lock()
	defer n.lock.Unlock()
	conn := n.conn
	n.conn = nil
	return conn.CloseLasting()
}

func (n *NftSetLinux) AddIP(addr netip.Addr, ttl time.Duration) error {
	if addr.Is4() && n.typ == Inet6 {
		return ErrInetMismatch
	}
	if addr.Is6() && n.typ == Inet4 {
		return ErrInetMismatch
	}
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.conn == nil {
		return ErrConnClosed
	}
	elem := nftables.SetElement{
		Key: addr.AsSlice(),
	}
	if ttl > 0 {
		elem.Timeout = ttl
	}
	err := n.conn.SetAddElements(n.set, []nftables.SetElement{elem})
	if err != nil {
		return err
	}
	return nil
}

func (n *NftSetLinux) AddCIDR(addr netip.Prefix, ttl time.Duration) error {
	if addr.Addr().Is4() && n.typ == Inet6 {
		return ErrInetMismatch
	}
	if addr.Addr().Is6() && n.typ == Inet4 {
		return ErrInetMismatch
	}
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.conn == nil {
		return ErrConnClosed
	}
	r := netipx.RangeOfPrefix(addr)
	startElem := nftables.SetElement{
		Key: r.From().AsSlice(),
	}
	endElem := nftables.SetElement{
		Key:         r.To().Next().AsSlice(),
		IntervalEnd: true,
	}
	if ttl > 0 {
		startElem.Timeout = ttl
		endElem.Timeout = ttl
	}
	err := n.conn.SetAddElements(n.set, []nftables.SetElement{startElem, endElem})
	if err != nil {
		return err
	}
	return nil
}

func (n *NftSetLinux) DelIP(addr netip.Addr) error {
	if addr.Is4() && n.typ == Inet6 {
		return ErrInetMismatch
	}
	if addr.Is6() && n.typ == Inet4 {
		return ErrInetMismatch
	}
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.conn == nil {
		return ErrConnClosed
	}
	elem := nftables.SetElement{
		Key: addr.AsSlice(),
	}
	err := n.conn.SetDeleteElements(n.set, []nftables.SetElement{elem})
	if err != nil {
		return err
	}
	return nil
}

func (n *NftSetLinux) DelCIDR(addr netip.Prefix) error {
	if addr.Addr().Is4() && n.typ == Inet6 {
		return ErrInetMismatch
	}
	if addr.Addr().Is6() && n.typ == Inet4 {
		return ErrInetMismatch
	}
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.conn == nil {
		return ErrConnClosed
	}
	r := netipx.RangeOfPrefix(addr)
	startElem := nftables.SetElement{
		Key: r.From().AsSlice(),
	}
	endElem := nftables.SetElement{
		Key:         r.To().Next().AsSlice(),
		IntervalEnd: true,
	}
	err := n.conn.SetDeleteElements(n.set, []nftables.SetElement{startElem, endElem})
	if err != nil {
		return err
	}
	return nil
}

func (n *NftSetLinux) FlushAll() error {
	n.lock.Lock()
	defer n.lock.Unlock()
	if n.conn == nil {
		return ErrConnClosed
	}
	n.conn.FlushSet(n.set)
	return nil
}
