package ttlstore

import (
	"encoding/base32"
	"fmt"
	"net/http"

	"github.com/gorilla/securecookie"
	"github.com/gorilla/sessions"
	"github.com/jellydator/ttlcache/v3"
)

// TTLStore stores gorilla sessions in TTL
type TTLStore struct {
	Codecs  []securecookie.Codec
	Options *sessions.Options
	keyPrefix string
	cache *ttlcache.Cache[string, []byte]
}

func NewTTLStore(keyPairs [][]byte, options ...ttlcache.Option[string, []byte]) *TTLStore {
	store := TTLStore{
		Codecs: securecookie.CodecsFromPairs(keyPairs...),
		Options: &sessions.Options{
			Path:   "/",
			MaxAge: 86400 * 30,
		},
		keyPrefix: "session_",
		cache: ttlcache.New(options...),
	}
	return &store
}

func (m *TTLStore) Get(r *http.Request, name string) (*sessions.Session, error) {
	return sessions.GetRegistry(r).Get(m, name)
}

func (store *TTLStore) New(r *http.Request, name string) (*sessions.Session, error) {
	session := sessions.NewSession(store, name)
	options := *store.Options
	session.Options = &options
	session.IsNew = true
	var err error
	if c, errCookie := r.Cookie(name); errCookie == nil {
		err = securecookie.DecodeMulti(name, c.Value, &session.ID, store.Codecs...)
		if err == nil {
			err = store.load(session)
			session.IsNew = err != nil
		}
	}
	return session, err
}

var base32RawStdEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

func (store *TTLStore) Save(r *http.Request, w http.ResponseWriter, session *sessions.Session) error {
	if session.Options.MaxAge <= 0 {
		if err := store.erase(session); err != nil {
			return err
		}
		http.SetCookie(w, sessions.NewCookie(session.Name(), "", session.Options))
		return nil
	}

	if session.ID == "" {
		session.ID = base32RawStdEncoding.EncodeToString(securecookie.GenerateRandomKey(32))
	}
	if err := store.save(session); err != nil {
		return err
	}
	encoded, err := securecookie.EncodeMulti(session.Name(), session.ID,
		store.Codecs...)
	if err != nil {
		return err
	}
	http.SetCookie(w, sessions.NewCookie(session.Name(), encoded, session.Options))
	return nil
}

func (store *TTLStore) MaxAge(age int) {
	store.Options.MaxAge = age

	for _, codec := range store.Codecs {
		if sc, ok := codec.(*securecookie.SecureCookie); ok {
			sc.MaxAge(age)
		}
	}
}

func (store *TTLStore) save(session *sessions.Session) error {
	encoded, err := securecookie.EncodeMulti(session.Name(), session.Values,
		store.Codecs...)
	if err != nil {
		return err
	}
	store.cache.Set(store.keyPrefix+session.ID, []byte(encoded), ttlcache.DefaultTTL)
	return nil
}

func (store *TTLStore) load(session *sessions.Session) error {
	item := store.cache.Get(store.keyPrefix+session.ID)
	if item == nil || item.IsExpired() {
		return fmt.Errorf("could not find session from cache")
	}
	data := item.Value()
	if err := securecookie.DecodeMulti(session.Name(), string(data), &session.Values, store.Codecs...); err != nil {
		return err
	}
	return nil
}

func (store *TTLStore) erase(session *sessions.Session) error {
	if _, ok := store.cache.GetAndDelete(store.keyPrefix+session.ID); !ok {
		return fmt.Errorf("could not find session from cache")
	}
	return nil
}

func (store *TTLStore) SetKeyPrefix(keyPrefix string) {
	store.keyPrefix = keyPrefix
}
